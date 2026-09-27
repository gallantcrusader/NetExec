"""Offline registry checks distinguish absence, access failure, and configuration."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.helpers import registry
from nxc.modules import install_elevated, runasppl, uac
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize(("module_type", "value", "enabled"), [(uac.NXCModule, 1, True), (uac.NXCModule, 0, False), (runasppl.NXCModule, 1, True), (runasppl.NXCModule, 2, True), (runasppl.NXCModule, 0, False)])
def test_registry_modules_return_values_and_close_handles(monkeypatch, module_type, value, enabled):
    remote = Mock()
    monkeypatch.setattr(registry, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(registry.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    monkeypatch.setattr(registry.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "key"}))
    monkeypatch.setattr(registry.rrp, "hBaseRegQueryValue", Mock(return_value=(4, value)))
    close = Mock()
    monkeypatch.setattr(registry.rrp, "hBaseRegCloseKey", close)
    module = module_type()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=object(), host="offline.invalid"))
    validate_module_result(module, result, "smb", "offline.invalid")
    assert result.data.value == value
    assert result.data.enabled is enabled
    assert result.data.present
    assert result.status is (ResultStatus.SUCCESS if enabled else ResultStatus.NEGATIVE)
    assert [call.args[1] for call in close.call_args_list] == ["key", "root"]
    remote.finish.assert_called_once()


@pytest.mark.parametrize("error_code", [2, 5])
@pytest.mark.parametrize("module_type", [uac.NXCModule, runasppl.NXCModule])
def test_missing_registry_value_is_not_access_failure(monkeypatch, error_code, module_type):
    remote = Mock()
    monkeypatch.setattr(registry, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(registry.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    monkeypatch.setattr(registry.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "key"}))
    monkeypatch.setattr(registry.rrp, "hBaseRegQueryValue", Mock(side_effect=registry.rrp.DCERPCSessionError(error_code=error_code)))
    monkeypatch.setattr(registry.rrp, "hBaseRegCloseKey", Mock())
    result = module_type().on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=object(), host="offline.invalid"))
    assert result.status is (ResultStatus.NEGATIVE if error_code == 2 else ResultStatus.FAILED)
    assert result.data.enabled is None
    assert result.data.value is None
    assert not result.data.present
    remote.finish.assert_called_once()


def test_cleanup_failure_retains_observed_value(monkeypatch):
    remote = Mock()
    monkeypatch.setattr(registry, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(registry.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    monkeypatch.setattr(registry.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "key"}))
    monkeypatch.setattr(registry.rrp, "hBaseRegQueryValue", Mock(return_value=(4, 1)))
    close = Mock(side_effect=[RuntimeError("close failed"), None])
    monkeypatch.setattr(registry.rrp, "hBaseRegCloseKey", close)
    result = uac.NXCModule().on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=object(), host="offline.invalid"))
    assert result.status is ResultStatus.FAILED
    assert result.data.enabled is True
    assert "close failed" in result.error
    assert close.call_count == 2
    remote.finish.assert_called_once()


def test_registry_startup_failure_still_finishes(monkeypatch):
    remote = Mock()
    remote.enableRegistry.side_effect = RuntimeError("connection failed")
    monkeypatch.setattr(registry, "RemoteOperations", Mock(return_value=remote))
    result = registry.read_registry_value(SimpleNamespace(conn=object()), "key", "value")
    assert result.error == "connection failed"
    remote.finish.assert_called_once()


@pytest.mark.parametrize(("machine", "user", "enabled", "failed"), [
    (registry.RegistryValue(True, 1, 4), registry.RegistryValue(True, 1, 4), True, False),
    (registry.RegistryValue(True, 1, 4), registry.RegistryValue(True, 0, 4), False, False),
    (registry.RegistryValue(True, 1, 4), registry.RegistryValue(), False, False),
    (registry.RegistryValue(True, 0, 4), None, False, False),
    (registry.RegistryValue(), None, False, False),
    (registry.RegistryValue(error="machine access denied"), None, None, True),
    (registry.RegistryValue(True, 1, 4), registry.RegistryValue(error="user access denied"), None, True),
])
def test_install_elevated_retains_both_observations(monkeypatch, machine, user, enabled, failed):
    reader = Mock(side_effect=[machine, user])
    monkeypatch.setattr(install_elevated, "read_registry_value", reader)
    module = install_elevated.NXCModule()
    fake = SimpleNamespace(conn=object(), host="offline.invalid")
    result = module.on_admin_login(SimpleNamespace(log=Mock()), fake)
    validate_module_result(module, result, "smb", fake.host)
    assert result.data.enabled is enabled
    assert result.data.machine is machine
    assert result.data.current_user is user
    assert result.status is (ResultStatus.FAILED if failed else ResultStatus.SUCCESS if enabled else ResultStatus.NEGATIVE)
    assert reader.call_count == (2 if user is not None else 1)
    if user is not None:
        assert reader.call_args.kwargs == {"hive": "HKCU"}


def test_registry_current_user_hive_is_selected(monkeypatch):
    remote = Mock()
    machine_root = Mock()
    user_root = Mock(return_value={"phKey": "user"})
    monkeypatch.setattr(registry, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(registry.rrp, "hOpenLocalMachine", machine_root)
    monkeypatch.setattr(registry.rrp, "hOpenCurrentUser", user_root)
    monkeypatch.setattr(registry.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "key"}))
    monkeypatch.setattr(registry.rrp, "hBaseRegQueryValue", Mock(return_value=(4, 1)))
    monkeypatch.setattr(registry.rrp, "hBaseRegCloseKey", Mock())
    result = registry.read_registry_value(SimpleNamespace(conn=object()), "key", "name", hive="HKCU")
    assert result.value == 1
    machine_root.assert_not_called()
    user_root.assert_called_once()
    remote.finish.assert_called_once()
