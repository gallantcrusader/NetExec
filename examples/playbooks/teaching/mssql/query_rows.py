"""Run a SELECT over MSSQL and read one row's columns.

Connect, run a SELECT with ``sql.query(query=...)``, take the single row with
``.one()`` (a dict), then read individual columns by name.
Example: nxc playbook 10.60.0.22 examples/playbooks/teaching/mssql/query_rows.py -u jon.snow -p iknownothing -d north.sevenkingdoms.local
"""

from dataclasses import dataclass


@dataclass
class Identity:
    login_name: str | None = None
    is_sysadmin: int | None = None


IDENTITY = "SELECT SUSER_SNAME() AS login_name, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"


def run(host):
    host.defaults(stop_on_error=False)
    sql = host.mssql()
    if not sql.authenticated:
        return host.finding("mssql_query_rows", ok=False, error="No MSSQL login established")

    row = sql.query(query=IDENTITY).one()  # one() -> single dict, columns keyed by alias
    data = Identity(login_name=row["login_name"], is_sysadmin=row["is_sysadmin"])
    return host.finding("mssql_query_rows", ok=True, data=data, inputs={"query": IDENTITY})
