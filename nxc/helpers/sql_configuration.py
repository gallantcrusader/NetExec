"""Observed SQL configuration changes with temporary-setting restoration."""

from dataclasses import dataclass, field

from nxc.playbooks.results import ActionResult, ResultStatus


@dataclass
class SQLConfigurationData:
    action: str
    linked_server: str | None
    requested_value: int
    before: dict = field(default_factory=dict)
    observed: dict = field(default_factory=dict)
    completed: bool = False
    verified: bool = False
    restoration_required: bool = False
    restored: bool | None = None
    queries: list[dict] = field(default_factory=list)


def configuration_query(connection, data, statement):
    query = statement if data.linked_server is None else "EXEC ('" + statement.replace("'", "''") + "') AT [" + data.linked_server.replace("]", "]]") + "];"
    step = {"query": query, "rows": [], "error": None}
    data.queries.append(step)
    try:
        step["rows"] = connection.conn.sql_query(query) or []
        if connection.conn.lastError:
            raise RuntimeError(str(connection.conn.lastError))
    except Exception as e:
        step["error"] = str(e) or type(e).__name__
        raise
    return step["rows"]


def read_configuration(connection, data):
    rows = configuration_query(connection, data, "SELECT name, CAST(value AS INT) AS configured, CAST(value_in_use AS INT) AS running FROM sys.configurations WHERE name IN ('show advanced options', 'xp_cmdshell');")
    values = {row["name"]: {"configured": row["configured"], "running": row["running"]} for row in rows}
    if set(values) != {"show advanced options", "xp_cmdshell"}:
        raise ValueError("SQL configuration query did not return both required settings")
    return values


def change_cmdshell(context, connection, module_name, action, linked_server=None):
    data = SQLConfigurationData(action, linked_server, int(action == "enable"))
    errors = []
    try:
        data.before = read_configuration(connection, data)
        advanced = data.before["show advanced options"]
        if advanced["configured"] != advanced["running"]:
            raise ValueError("show advanced options has a pending configuration; cannot preserve it while applying RECONFIGURE")
        if advanced["running"] == 0:
            # An error may occur after the server applied the temporary change.
            data.restoration_required = True
            configuration_query(connection, data, "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
        configuration_query(connection, data, f"EXEC sp_configure 'xp_cmdshell', {data.requested_value}; RECONFIGURE;")
        data.completed = True
        data.observed = read_configuration(connection, data)
        data.verified = data.observed["xp_cmdshell"] == {"configured": data.requested_value, "running": data.requested_value}
        if not data.verified:
            errors.append("xp_cmdshell read-back did not match the requested configuration")
    except Exception as e:
        errors.append(str(e) or type(e).__name__)
    finally:
        if data.restoration_required:
            data.restored = False
            try:
                configuration_query(connection, data, "EXEC sp_configure 'show advanced options', 0; RECONFIGURE;")
                data.observed = read_configuration(connection, data)
                data.restored = data.observed["show advanced options"] == data.before["show advanced options"]
                if not data.restored:
                    errors.append("show advanced options restoration did not match its original configuration")
                # Final observations supersede an earlier successful read-back.
                if data.completed:
                    data.verified = data.observed["xp_cmdshell"] == {"configured": data.requested_value, "running": data.requested_value}
                    if not data.verified:
                        errors.append("Final xp_cmdshell configuration did not match the requested value")
            except Exception as e:
                errors.append(f"Restoring show advanced options: {str(e) or type(e).__name__}")
    for error in errors:
        context.log.fail(error)
    if not errors:
        context.log.success(f"xp_cmdshell {action}: requested configuration verified")
    return ActionResult("mssql", module_name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS, data, error="; ".join(errors) or None)
