"""Observe SQL privilege and linked-server paths on the two GOAD SQL hosts.

Supply an existing GOAD account through -u/-p/-d and use --dns-server 10.60.0.10.
This queries identity/permissions and exercises the configured linked login with
a SELECT batch. It does not enable command execution or change SQL permissions.
"""

from nxc.playbooks.results import ResultStatus


def run(host):
    links = {"10.60.0.22": "BRAAVOS", "10.60.0.23": "CASTELBLACK"}
    if host.target not in links:
        raise ValueError("This GOAD playbook expects 10.60.0.22 or 10.60.0.23")
    sql = host.mssql()
    if not sql.ok:
        return
    sql.query(query="SELECT @@SERVERNAME AS server_name, ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS effective_login, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin")
    sql.module("enum_impersonate")
    linked = sql.module("enum_links")
    if linked.status is ResultStatus.SUCCESS and any(row["SRV_NAME"].upper() == links[host.target] for row in linked.data.servers):
        sql.module(
            "exec_on_link", linked_server=links[host.target],
            command="SELECT @@SERVERNAME AS server_name, ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS effective_login, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin",
        )
