"""Registry read/write/delete paths tested only with fake RPC calls."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("operation", ["query", "set", "delete"])
@pytest.mark.parametrize("missing", [False, True])
def test_registry_operation_records_and_single_cleanup(monkeypatch, operation, missing):
    code = import_module("nxc.modules.reg-query")
    context = SimpleNamespace(log=Mock())
    module = code.NXCModule()
    options = {"PATH": r"HKEY_LOCAL_MACHINE\Software\Test", "KEY": ""}
    if operation == "set":
        options.update(VALUE="42", TYPE="REG_DWORD")
    elif operation == "delete":
        options["DELETE"] = "true"
    module.options(context, options)
    remote = Mock()
    monkeypatch.setattr(code, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(code.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    opened = Mock(return_value={"phkResult": "key"})
    monkeypatch.setattr(code.rrp, "hBaseRegOpenKey", opened)
    query = Mock(return_value=(4, 7))
    if missing:
        query.side_effect = code.rrp.DCERPCSessionError(error_code=2)
    monkeypatch.setattr(code.rrp, "hBaseRegQueryValue", query)
    set_value, delete, close = Mock(), Mock(), Mock()
    monkeypatch.setattr(code.rrp, "hBaseRegSetValue", set_value)
    monkeypatch.setattr(code.rrp, "hBaseRegDeleteValue", delete)
    monkeypatch.setattr(code.rrp, "hBaseRegCloseKey", close)
    result = module.on_admin_login(context, SimpleNamespace(host="offline.invalid", conn=Mock()))
    validate_module_result(module, result, "smb", "offline.invalid")
    assert result.status is (ResultStatus.NEGATIVE if missing and operation != "set" else ResultStatus.SUCCESS)
    assert result.data.operation == operation
    assert result.data.observed.present is not missing
    assert opened.call_args.args[2] == r"Software\Test"
    assert set_value.call_count == (1 if operation == "set" else 0)
    assert delete.call_count == (1 if operation == "delete" and not missing else 0)
    if operation == "set":
        assert set_value.call_args.args[-2:] == (4, 42)
    assert [call.args[1] for call in close.call_args_list] == ["key", "root"]
    remote.finish.assert_called_once_with()


@pytest.mark.parametrize("options", [{"PATH": "HKLM\\Test"}, {"PATH": "HKLM\\Test", "KEY": "value", "VALUE": "1", "DELETE": "true"}, {"PATH": "HKLM\\Test", "KEY": "value", "VALUE": "wrong", "TYPE": "REG_DWORD"}])
def test_invalid_registry_options_exit_before_operations(options):
    with pytest.raises(SystemExit):
        import_module("nxc.modules.reg-query").NXCModule().options(SimpleNamespace(log=Mock()), options)


@pytest.mark.parametrize("failure", ["denied", "cleanup"])
def test_registry_failures_preserve_observation(monkeypatch, failure):
    code = import_module("nxc.modules.reg-query")
    module = code.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"PATH": r"HKLM\Software\Test", "KEY": "Value"})
    remote = Mock()
    monkeypatch.setattr(code, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(code.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    monkeypatch.setattr(code.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "key"}))
    query = Mock(return_value=(1, "observed"))
    if failure == "denied":
        query.side_effect = code.rrp.DCERPCSessionError(error_code=5)
    else:
        remote.finish.side_effect = RuntimeError("cleanup failed")
    monkeypatch.setattr(code.rrp, "hBaseRegQueryValue", query)
    close = Mock()
    monkeypatch.setattr(code.rrp, "hBaseRegCloseKey", close)
    result = module.on_admin_login(context, SimpleNamespace(host="offline.invalid", conn=Mock()))
    assert result.status is ResultStatus.FAILED
    assert result.error
    assert result.data.completed is (failure == "cleanup")
    assert result.data.observed.value == ("observed" if failure == "cleanup" else None)
    assert close.call_count == 2
