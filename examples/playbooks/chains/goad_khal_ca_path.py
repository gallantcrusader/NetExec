"""Verify Khal's two configured routes toward the Braavos CA host.

Start on Meereen with Khal's domain credential and allow Braavos. This checks
local administrator access and reads ESC4 template ACLs. It changes no AD, CA,
or host configuration.
"""

from dataclasses import dataclass, field

from nxc.playbooks.access import assess_dacl
from nxc.playbooks.results import ActionResult, CredentialRef, ResultStatus


@dataclass
class KhalCAPath:
    credential: CredentialRef | None = None
    directory_sids: list[str] = field(default_factory=list)
    dothraki_member: bool = False
    template_ace_indices: list[int] = field(default_factory=list)
    template_assessment: object | None = None
    published_ca: list[dict] = field(default_factory=list)
    braavos_admin: bool | None = None
    local_administrators: dict = field(default_factory=dict)
    ca_rpc_observed: bool | None = None
    web_enrollment_observed: bool | None = None
    evidence_indices: list[int] = field(default_factory=list)
    reached_ca_host: bool = False
    reason: str | None = None


def run(host):
    if host.target != "10.60.0.12":
        raise ValueError("Start this GOAD path on Meereen at 10.60.0.12")
    braavos = host.at("10.60.0.23")
    data = KhalCAPath()

    def finish(reason=None):
        data.reason = reason
        host.record(ActionResult("playbook", "goad_khal_ca_path", host.target, ResultStatus.SUCCESS if data.reached_ca_host else ResultStatus.NEGATIVE, data, inputs={"destination": braavos.target}))

    ldap = host.ldap()
    data.evidence_indices.append(len(host.run.results) - 1)
    if not ldap.ok or not ldap.result.data.authenticated:
        finish("Khal's directory login was not established")
        return
    if ldap.connection.username.casefold() != "khal.drogo":
        raise ValueError("This GOAD path requires khal.drogo as the initial identity")
    data.credential = ldap.result.data.credential
    if data.credential is None:
        finish("Directory login has no reusable database credential reference")
        return
    token = ldap.module("token-groups", principal="khal.drogo")
    data.evidence_indices.append(len(host.run.results) - 1)
    data.directory_sids = token.data.directory_sids
    group = ldap.groups(groups="Dothraki")
    data.evidence_indices.append(len(host.run.results) - 1)
    data.dothraki_member = any(str(member.get("sAMAccountName", "")).casefold() == "khal.drogo" for member in group.data.members)
    template = ldap.module("daclread", target_dn="CN=ESC4,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local", principal="khal.drogo", ace_type="all")
    data.evidence_indices.append(len(host.run.results) - 1)
    for obj in template.data.objects:
        data.template_ace_indices.extend(index for index in obj["matches"] if obj["descriptor"]["aces"][index]["access"] == "allowed")
        data.template_assessment = assess_dacl(obj["descriptor"], [*data.directory_sids, "S-1-1-0", "S-1-5-11", "S-1-5-2"], 0xF01FF, target_sid=obj["sid"])
    cas = ldap.module("adcs")
    data.evidence_indices.append(len(host.run.results) - 1)
    data.published_ca = [service for service in cas.data.services if str(service["attributes"].get("dNSHostName", "")).casefold() == "braavos.essos.local"]
    smb = braavos.smb(credential=data.credential)
    data.evidence_indices.append(len(host.run.results) - 1)
    if not smb.ok or not smb.result.data.authenticated:
        finish("Stored Khal credential did not authenticate to Braavos SMB")
        return
    data.braavos_admin = smb.result.data.admin_privileges
    members = smb.local_groups(local_groups="Administrators", stop_on_error=False)
    data.evidence_indices.append(len(host.run.results) - 1)
    if members.ok:
        data.local_administrators = members.data.members
    ca = smb.module("enum_ca", stop_on_error=False)
    data.evidence_indices.append(len(host.run.results) - 1)
    if ca.ok:
        data.ca_rpc_observed = ca.data.adcs_found
        data.web_enrollment_observed = ca.data.web_enrollment_found
    data.reached_ca_host = data.braavos_admin is True and bool(data.published_ca) and data.ca_rpc_observed is True
    finish(None if data.reached_ca_host else "Braavos CA publication, CA RPC, or SMB administrator access was not verified")
