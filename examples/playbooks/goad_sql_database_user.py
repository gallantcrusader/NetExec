"""Verify Arya's configured dbo impersonation routes without persistent changes."""


def run(host):
    if host.target != "10.60.0.22":
        raise ValueError("This GOAD database-user playbook expects Castelblack at 10.60.0.22")
    sql = host.mssql()
    if not sql.ok:
        return
    query = "SELECT ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS effective_login, DB_NAME() AS database_name, USER_NAME() AS database_user"
    before = sql.query(query=query)
    if before.data.rows[0][0].lower() != "north\\arya.stark":
        raise ValueError("This playbook verifies the configured NORTH\\arya.stark routes")
    for database in ("master", "msdb"):
        result = sql.module("check-impersonation", user="dbo", database=database)
        assert result.data.impersonated
        assert result.data.restored
        during = next(row for row in result.data.observations if row["stage"] == 1)
        assert during["database_name"] == database
        assert during["database_user"] == "dbo"
        assert during["controls_database"] == 1
        after = sql.query(query=query)
        assert after.data.rows == before.data.rows, "Identity or database changed after restoration"
        assert host.mssql() is sql, "Shared SQL session was replaced unexpectedly"
