"""Offline linked batches preserve quoting, output, and SQL failures."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules import exec_on_link, link_xpcmd
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("module_class", [exec_on_link.NXCModule, link_xpcmd.NXCModule])
@pytest.mark.parametrize("outcome", ["rows", "empty", "error", "exception"])
def test_linked_sql_outcomes(module_class, outcome):
    module = module_class()
    context = SimpleNamespace(log=Mock())
    command = "SELECT 'quoted';"
    module.options(context, {"LINKED_SERVER": "server]name", "COMMAND": command, "CMD": command})
    rows = [{"output": "  spaced  ", "extra": 1}, {"output": None}, {"output": ""}]
    sql = SimpleNamespace(lastError="partial SQL error" if outcome == "error" else False,
                          sql_query=Mock(return_value=[] if outcome == "empty" else rows))
    if outcome == "exception":
        sql.sql_query.side_effect = RuntimeError("transport failed")
    connection = SimpleNamespace(conn=sql, host="offline.invalid")
    result = module.on_login(context, connection)
    validate_module_result(module, result, "mssql", connection.host)
    assert result.status is (ResultStatus.FAILED if outcome in ("error", "exception") else ResultStatus.SUCCESS)
    assert result.data.completed is (outcome in ("rows", "empty"))
    assert result.data.command == command
    query = sql.sql_query.call_args.args[0]
    if module.name == "exec_on_link":
        assert query == "EXEC ('SELECT ''quoted'';') AT [server]]name];"
        assert result.data.output == []
    else:
        assert query == "EXEC ('EXEC xp_cmdshell ''SELECT ''''quoted'''';'';') AT [server]]name];"
        assert result.data.output == (["  spaced  ", None, ""] if outcome in ("rows", "error") else [])
    assert result.data.rows == (rows if outcome in ("rows", "error") else [])


@pytest.mark.parametrize("module_class", [exec_on_link.NXCModule, link_xpcmd.NXCModule])
def test_linked_command_requires_options(module_class):
    with pytest.raises(SystemExit):
        module_class().options(SimpleNamespace(log=Mock()), {"LINKED_SERVER": "server"})
