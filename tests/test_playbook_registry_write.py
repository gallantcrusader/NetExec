"""Registry writes are mocked; distinguish completion from read-back."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import nxc.helpers.registry as registry
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("failure", [None, "write", "read", "mismatch", "cleanup"])
def test_registry_write_completion_and_verification(monkeypatch, failure):
    remote = Mock()
    monkeypatch.setattr(registry, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(registry.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    monkeypatch.setattr(registry.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "key"}))
    write, read, close = Mock(), Mock(return_value=(4, 1)), Mock()
    monkeypatch.setattr(registry.rrp, "hBaseRegSetValue", write)
    monkeypatch.setattr(registry.rrp, "hBaseRegQueryValue", read)
    monkeypatch.setattr(registry.rrp, "hBaseRegCloseKey", close)
    if failure == "write":
        write.side_effect = RuntimeError("write denied")
    elif failure == "read":
        read.side_effect = RuntimeError("read denied")
    elif failure == "mismatch":
        read.return_value = (4, 0)
    elif failure == "cleanup":
        remote.finish.side_effect = RuntimeError("cleanup denied")
    result = registry.write_registry_value(SimpleNamespace(conn=Mock()), "Test", "Value", 1, 4)
    assert result.completed is (failure != "write")
    assert result.verified is (failure in (None, "cleanup"))
    assert bool(result.error) is (failure is not None)
    if failure == "read":
        assert result.observed.error == "read denied"
    assert [call.args[1] for call in close.call_args_list] == ["key", "root"]
    remote.finish.assert_called_once_with()


@pytest.mark.parametrize(("action", "value"), [("enable", 0), ("disable", 1)])
def test_remote_uac_reports_requested_setting(monkeypatch, action, value):
    code = import_module("nxc.modules.remote-uac")
    write = Mock(return_value=registry.RegistryWrite(value, 4, completed=True, verified=True))
    monkeypatch.setattr(code, "write_registry_value", write)
    module = code.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"ACTION": action})
    result = module.on_admin_login(context, SimpleNamespace(host="offline.invalid"))
    assert result.status is ResultStatus.SUCCESS
    assert result.data.action == action
    assert write.call_args.args[-2:] == (value, 4)


def test_remote_uac_missing_action_stops_at_options():
    with pytest.raises(SystemExit):
        import_module("nxc.modules.remote-uac").NXCModule().options(SimpleNamespace(log=Mock()), {})
