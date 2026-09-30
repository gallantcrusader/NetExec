"""Verify GOAD login impersonation routes and restoration on the shared session."""


def run(host):
    if host.target not in {"10.60.0.22", "10.60.0.23"}:
        raise ValueError("This GOAD playbook expects one of the two SQL member servers")
    sql = host.mssql()
    if not sql.ok:
        return
    identity = sql.query(query="SELECT ORIGINAL_LOGIN() AS original_login")
    original = identity.data.rows[0][0]
    routes = {
        ("10.60.0.22", "north\\brandon.stark"): "NORTH\\jon.snow",
        ("10.60.0.22", "north\\samwell.tarly"): "sa",
        ("10.60.0.23", "essos\\jorah.mormont"): "sa",
    }
    target = routes.get((host.target, original.lower()))
    if target is None:
        raise ValueError(f"No login impersonation route configured here for {original}")
    result = sql.module("check-impersonation", login=target)
    assert result.data.impersonated
    assert result.data.restored
    during = next(row for row in result.data.observations if row["stage"] == 1)
    assert during["is_sysadmin"] == 1, "Impersonated identity was not SQL sysadmin"
    after = sql.query(query="SELECT SUSER_SNAME() AS effective_login")
    assert after.data.rows[0][0] == original, "Follow-up query used an unexpected identity"
    assert host.mssql() is sql, "Shared SQL session was replaced unexpectedly"
