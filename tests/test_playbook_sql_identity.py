"""Offline checks for SQL identity observations and unusable-session handling."""

from argparse import Namespace
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import ConnectionData, HostContext, ProtocolSession
from nxc.playbooks import runner


def observation(stage, login="NORTH\\samwell.tarly", error=None):
    return {"stage": stage, "server_name": "SQL", "original_login": "NORTH\\samwell.tarly", "effective_login": login, "login_sid": login.encode(), "database_name": "master", "database_user": "guest", "is_sysadmin": int(login == "sa"), "is_db_owner": int(login == "sa"), "controls_database": int(login == "sa"), "controls_server": int(login == "sa"), "error_number": 1 if error else None, "error_message": error}


@pytest.mark.parametrize("failure", [None, "denied", "missing_after", "wrong_after", "transport", "sql_error", "duplicate"])
def test_impersonation_result_and_restoration(failure):
    module = import_module("nxc.modules.check-impersonation").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"LOGIN": "sa"})
    rows = [observation(0), observation(1, "sa"), observation(2)]
    if failure == "denied":
        rows = [observation(0, error="access denied"), observation(2, error="access denied")]
    elif failure == "missing_after":
        rows.pop()
    elif failure == "wrong_after":
        rows[-1] = observation(2, "sa")
    elif failure == "duplicate":
        rows.append(observation(2))
    conn = SimpleNamespace(host="offline.invalid", conn=Mock(lastError="SQL failure" if failure == "sql_error" else None), close_session=Mock())
    conn.conn.sql_query.return_value = rows
    if failure == "transport":
        conn.conn.sql_query.side_effect = OSError("connection lost")
    result = module.on_login(context, conn)
    validate_module_result(module, result, "mssql", conn.host)
    assert result.status is (ResultStatus.SUCCESS if failure is None else ResultStatus.FAILED)
    discarded = failure in {"missing_after", "wrong_after", "transport", "duplicate"}
    assert result.data.session_discarded is discarded
    assert result.data.restored is not discarded
    assert conn.close_session.call_count == int(discarded)


def test_login_is_escaped_as_sql_literal():
    module = import_module("nxc.modules.check-impersonation").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"LOGIN": "O'Brien"})
    conn = SimpleNamespace(host="offline.invalid", conn=Mock(lastError=None), close_session=Mock())
    conn.conn.sql_query.return_value = [observation(0), observation(1, "O'Brien"), observation(2)]
    module.on_login(context, conn)
    assert "EXECUTE AS LOGIN = N'O''Brien';" in conn.conn.sql_query.call_args.args[0]


@pytest.mark.parametrize("failure", [None, "denied", "wrong_database", "preflight"])
def test_database_user_context_and_restoration(failure):
    module = import_module("nxc.modules.check-impersonation").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"USER": "dbo", "DATABASE": "ms]db"})
    during = {**observation(1), "database_name": "ms]db", "database_user": "dbo", "is_db_owner": 1, "controls_database": 1}
    rows = [observation(0), during, observation(2)]
    if failure == "denied":
        rows = [observation(0, error="user denied"), observation(2, error="user denied")]
    elif failure == "wrong_database":
        rows[-1]["database_name"] = "ms]db"
    conn = SimpleNamespace(host="offline.invalid", conn=Mock(lastError=None), close_session=Mock())
    conn.conn.sql_query.side_effect = [OSError("preflight failed")] if failure == "preflight" else [[{"database_name": "master"}], rows]
    result = module.on_login(context, conn)
    validate_module_result(module, result, "mssql", conn.host)
    assert result.status is (ResultStatus.SUCCESS if failure is None else ResultStatus.FAILED)
    assert result.data.session_discarded is (failure == "wrong_database")
    if failure == "preflight":
        conn.conn.sql_query.assert_called_once()
        conn.close_session.assert_not_called()
    else:
        statement = conn.conn.sql_query.call_args.args[0]
        assert "USE [ms]]db];" in statement
        assert "EXECUTE AS USER = N'dbo';" in statement
        assert statement.index("REVERT;") < statement.index("USE [master];")
        assert result.data.restored is (failure != "wrong_database")


@pytest.mark.parametrize("options", [{}, {"LOGIN": "sa", "USER": "dbo"}, {"LOGIN": "sa", "DATABASE": "master"}])
def test_invalid_impersonation_options(options):
    module = import_module("nxc.modules.check-impersonation").NXCModule()
    with pytest.raises(SystemExit):
        module.options(SimpleNamespace(log=Mock()), options)


def test_unusable_session_blocks_subsequent_actions_and_modules():
    host = HostContext("offline.invalid", [])
    conn = SimpleNamespace(host=host.target, playbook_unusable_reason="restoration unknown", query=Mock())
    session = ProtocolSession(host, "mssql", conn, Namespace(query=None), None, None, ActionResult("mssql", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False)))
    assert not session.ok
    assert session.action("query", stop_on_error=False).status is ResultStatus.FAILED
    assert session.module("enum_links", stop_on_error=False).status is ResultStatus.FAILED
    conn.query.assert_not_called()


def test_unusable_cached_session_is_replaced(monkeypatch):
    class OfflineSQL:
        def __init__(self, args, db, target, defer_flow=False):
            self.host = target
            self.username = ""
            self.transport_open = True
            self.close_session = Mock()

        def open_session(self, anonymous=False):
            return True

    host = HostContext("offline.invalid", [])
    host.protocols = {"mssql": {"path": "sql", "dbpath": "db"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(mssql=OfflineSQL) if path == "sql" else SimpleNamespace(database=lambda engine: object()))
    monkeypatch.setattr(runner, "create_db_engine", lambda path: Mock())
    old = host.mssql()
    old.connection.playbook_unusable_reason = "restoration unknown"
    new = host.mssql()
    assert new is not old
    assert new.ok
    assert not old.ok
    old.connection.close_session.assert_called_once()
    old.engine.dispose.assert_called_once()
    assert host.mssql() is new
    host.close()
