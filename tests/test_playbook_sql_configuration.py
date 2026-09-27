"""Offline configuration state and failures for local and linked SQL sessions."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules import enable_cmdshell, link_enable_cmdshell
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("module_class", [enable_cmdshell.NXCModule, link_enable_cmdshell.NXCModule])
@pytest.mark.parametrize("action", ["enable", "disable"])
@pytest.mark.parametrize("scenario", ["normal", "already_advanced", "backup_error", "pending", "temporary_error", "change_error", "mismatch", "restore_error"])
def test_configuration_and_restoration(module_class, action, scenario):
    initial = 1 if scenario == "already_advanced" else 0
    state = {"show advanced options": {"configured": initial, "running": initial},
             "xp_cmdshell": {"configured": int(action == "disable"), "running": int(action == "disable")}}
    if scenario == "pending":
        state["show advanced options"]["configured"] = 1
    calls = []
    sql = SimpleNamespace(lastError=False)

    def query(statement):
        calls.append(statement)
        if module_class is link_enable_cmdshell.NXCModule:
            assert statement.endswith("') AT [server]]name];")
            statement = statement[len("EXEC ('"):-len("') AT [server]]name];")].replace("''", "'")
        sql.lastError = False
        if statement.startswith("SELECT"):
            if scenario == "backup_error":
                sql.lastError = "cannot read configuration"
                return []
            return [{"name": name, **values} for name, values in state.items()]
        if "'show advanced options', 1" in statement:
            state["show advanced options"] = {"configured": 1, "running": 1}
            if scenario == "temporary_error":
                sql.lastError = "temporary change failed after application"
        elif "'show advanced options', 0" in statement:
            if scenario == "restore_error":
                raise RuntimeError("restoration failed")
            state["show advanced options"] = {"configured": 0, "running": 0}
        elif "'xp_cmdshell'" in statement:
            if scenario == "change_error":
                sql.lastError = "change failed"
            elif scenario != "mismatch":
                value = int(action == "enable")
                state["xp_cmdshell"] = {"configured": value, "running": value}
        else:
            pytest.fail(f"Unexpected query {statement}")
        return []

    sql.sql_query = Mock(side_effect=query)
    connection = SimpleNamespace(conn=sql, host="offline.invalid")
    module = module_class()
    module.options(SimpleNamespace(log=Mock()), {"ACTION": action, "LINKED_SERVER": "server]name"})
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    validate_module_result(module, result, "mssql", connection.host)
    success = scenario in ("normal", "already_advanced")
    assert result.status is (ResultStatus.SUCCESS if success else ResultStatus.FAILED)
    if scenario in ("backup_error", "pending"):
        assert len(calls) == 1
        assert not result.data.completed
        assert not result.data.restoration_required
    elif scenario == "already_advanced":
        assert not result.data.restoration_required
        assert result.data.restored is None
        assert len(calls) == 3
    else:
        assert result.data.restoration_required
        assert result.data.restored is (scenario != "restore_error")
        assert any("advanced options" in call and ", 0; RECONFIGURE" in call for call in calls)
        if scenario == "temporary_error":
            assert not any("sp_configure" in call and "xp_cmdshell" in call for call in calls)
    if success:
        assert result.data.completed
        assert result.data.verified
        assert state["show advanced options"]["running"] == initial
    if scenario == "restore_error":
        assert result.data.completed
        assert result.data.verified
        assert "restoration failed" in result.error
    if scenario == "mismatch":
        assert result.data.completed
        assert not result.data.verified
    assert len(result.data.queries) == len(calls)
