"""Follow Jon's stored credential from Winterfell to both GOAD SQL servers.

Start at 10.60.0.11 with Jon's credentials and declare 10.60.0.22 and 10.60.0.23
using --allow-target. All SQL batches are SELECTs. The reached privilege is SQL
sysadmin; this does not establish Windows administrator or domain control.
"""

from dataclasses import dataclass, field

from nxc.playbooks.results import ActionResult, CredentialRef, ResultStatus


@dataclass
class SQLPathEvidence:
    source_credential: CredentialRef | None = None
    sql_credential: CredentialRef | None = None
    local_identity: dict = field(default_factory=dict)
    linked_identity: dict = field(default_factory=dict)
    evidence_indices: list[int] = field(default_factory=list)
    reached: bool = False
    privilege: str = "SQL sysadmin"
    reason: str | None = None


def run(host):
    if host.target != "10.60.0.11":
        raise ValueError("Start this GOAD path on Winterfell at 10.60.0.11")
    # Resolve allowed contexts before opening a connection, including the known
    # destination of the configured linked server. at() itself does no I/O.
    castelblack = host.at("10.60.0.22")
    braavos = host.at("10.60.0.23")
    data = SQLPathEvidence()

    def finish(reason=None):
        data.reason = reason
        host.record(ActionResult("playbook", "goad_cross_host_sql", host.target, ResultStatus.SUCCESS if data.reached else ResultStatus.NEGATIVE, data, inputs={"sql_host": castelblack.target, "linked_host": braavos.target}))

    ldap = host.ldap()
    data.evidence_indices.append(len(host.run.results) - 1)
    if not ldap.ok or not ldap.result.data.authenticated:
        finish("Initial directory authentication was not established")
        return
    data.source_credential = ldap.result.data.credential
    if data.source_credential is None:
        finish("Initial authentication has no reusable database credential reference")
        return
    sql = castelblack.mssql(credential=data.source_credential)
    data.evidence_indices.append(len(host.run.results) - 1)
    if not sql.ok or not sql.result.data.authenticated:
        finish("Stored credential did not establish SQL authentication on Castelblack")
        return
    data.sql_credential = sql.result.data.credential
    query = "SELECT @@SERVERNAME AS server_name, CAST(SERVERPROPERTY('MachineName') AS nvarchar(128)) AS machine_name, ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS effective_login, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"
    local = sql.query(query=query)
    data.evidence_indices.append(len(host.run.results) - 1)
    if len(local.data.rows) != 1:
        raise ValueError("SQL did not return exactly one local identity")
    data.local_identity = dict(zip(local.data.columns, local.data.rows[0], strict=True))
    if str(data.local_identity.get("machine_name")).upper() != "CASTELBLACK" or data.local_identity.get("is_sysadmin") != 1:
        finish("Castelblack SQL sysadmin prerequisite was not observed")
        return
    links = sql.module("enum_links")
    data.evidence_indices.append(len(host.run.results) - 1)
    if not any(row["SRV_NAME"].upper() == "BRAAVOS" for row in links.data.servers):
        finish("Configured BRAAVOS SQL link was not found")
        return
    linked = sql.module("exec_on_link", linked_server="BRAAVOS", command=query)
    data.evidence_indices.append(len(host.run.results) - 1)
    if len(linked.data.rows) != 1:
        raise ValueError("SQL did not return exactly one linked identity")
    data.linked_identity = linked.data.rows[0]
    data.reached = str(data.linked_identity.get("machine_name")).upper() == "BRAAVOS" and data.linked_identity.get("is_sysadmin") == 1
    if host.at(castelblack.target).mssql(credential=data.source_credential) is not sql or braavos.at(host.target).ldap() is not ldap:
        raise ValueError("The cross-host workflow did not reuse its original sessions")
    finish(None if data.reached else "Linked query did not observe Braavos SQL sysadmin")
