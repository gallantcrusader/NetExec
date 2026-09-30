"""MSSQL linked servers: enumerate links, then run a read-only SELECT over one.

List configured links with the ``enum_links`` module (``ModuleResult.data.servers``),
then execute a SELECT on the first link with ``exec_on_link`` and read the single row
with ``.one()``.
Example: nxc playbook 10.60.0.22 examples/playbooks/teaching/mssql/linked_servers.py -u jon.snow -p iknownothing -d north.sevenkingdoms.local
"""

from dataclasses import dataclass, field


@dataclass
class LinkedServers:
    links: list[str] = field(default_factory=list)
    linked_login: dict | None = None


def run(host):
    host.defaults(stop_on_error=False)
    data = LinkedServers()
    sql = host.mssql()
    if not sql.authenticated:
        return host.finding("mssql_linked_servers", ok=False, data=data, error="No MSSQL login established")

    data.links = [row["SRV_NAME"] for row in sql.module("enum_links").data.servers]
    if not data.links:
        return host.finding("mssql_linked_servers", ok=False, data=data, error="No linked servers configured")

    link = data.links[0]
    data.linked_login = sql.module("exec_on_link", linked_server=link, command="SELECT SUSER_SNAME() AS login").one()
    return host.finding("mssql_linked_servers", ok=True, data=data, inputs={"linked_server": link})
