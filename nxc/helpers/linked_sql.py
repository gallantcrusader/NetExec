"""Execute a linked-server SQL batch and preserve its outcome."""

from dataclasses import dataclass, field

from nxc.playbooks.results import ActionResult, ResultStatus


@dataclass
class LinkedSQLData:
    linked_server: str
    command: str
    query: str
    rows: list[dict] = field(default_factory=list)
    output: list = field(default_factory=list)
    completed: bool = False


def execute_linked_sql(context, connection, action, server, command, *, xp_cmdshell=False):
    statement = "EXEC xp_cmdshell '" + command.replace("'", "''") + "';" if xp_cmdshell else command
    query = "EXEC ('" + statement.replace("'", "''") + "') AT [" + server.replace("]", "]]") + "];"
    data = LinkedSQLData(server, command, query)
    error = None
    try:
        data.rows = connection.conn.sql_query(query) or []
        if connection.conn.lastError:
            error = str(connection.conn.lastError)
        else:
            data.completed = True
        if xp_cmdshell:
            data.output = [row["output"] for row in data.rows if "output" in row]
            for line in data.output:
                if line is not None:
                    context.log.highlight(str(line))
        else:
            context.log.display(f"Command output: {data.rows}")
    except Exception as e:
        error = str(e) or type(e).__name__
    if error:
        context.log.fail(error)
    elif data.completed:
        context.log.success("Linked-server SQL batch completed")
    return ActionResult("mssql", action, connection.host, ResultStatus.FAILED if error else ResultStatus.SUCCESS, data, error=error)
