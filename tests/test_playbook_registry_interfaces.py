"""Offline interface registry data and cleanup."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import nxc.modules.enum_interfaces as module_code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("failure", [None, "query", "cleanup"])
def test_registry_interface_records_and_cleanup(monkeypatch, failure):
    remote = Mock()
    monkeypatch.setattr(module_code, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(module_code.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    opens = Mock(side_effect=[{"phkResult": "base"}, {"phkResult": "interface"}, {"phkResult": "name"}])
    monkeypatch.setattr(module_code.rrp, "hBaseRegOpenKey", opens)
    monkeypatch.setattr(module_code.rrp, "hBaseRegQueryInfoKey", Mock(return_value={"lpcSubKeys": 1}))
    monkeypatch.setattr(module_code.rrp, "hBaseRegEnumKey", Mock(return_value={"lpNameOut": "{GUID}\x00"}))
    close = Mock()
    monkeypatch.setattr(module_code.rrp, "hBaseRegCloseKey", close)

    def query(rpc, handle, name):
        if name == "Name":
            return 1, "Ethernet\x00"
        if name == "EnableDHCP":
            return 4, 0
        if name == "IPAddress":
            if failure == "query":
                raise module_code.rrp.DCERPCSessionError(error_code=5)
            return 7, "192.0.2.1\x00192.0.2.2\x00\x00"
        raise module_code.rrp.DCERPCSessionError(error_code=2)

    monkeypatch.setattr(module_code.rrp, "hBaseRegQueryValue", query)
    if failure == "cleanup":
        remote.finish.side_effect = RuntimeError("finish failed")
    module = module_code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=Mock(), host="offline.invalid"))
    validate_module_result(module, result, "smb", "offline.invalid")
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    interface = result.data.interfaces[0]
    assert interface["id"] == "{GUID}"
    assert interface["values"]["EnableDHCP"].value == 0
    assert not interface["values"]["DhcpIPAddress"].present
    if failure != "query":
        assert interface["values"]["IPAddress"].value == "192.0.2.1\x00192.0.2.2\x00\x00"
    else:
        assert interface["values"]["IPAddress"].error
    assert [call.args[1] for call in close.call_args_list] == ["name", "interface", "base", "root"]
    assert "CurrentControlSet" in opens.call_args_list[-1].args[2]
    remote.finish.assert_called_once_with()


def test_registry_start_failure_still_finishes(monkeypatch):
    remote = Mock()
    remote.enableRegistry.side_effect = RuntimeError("registry unavailable")
    monkeypatch.setattr(module_code, "RemoteOperations", Mock(return_value=remote))
    result = module_code.NXCModule().on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=Mock(), host="offline.invalid"))
    assert result.status is ResultStatus.FAILED
    assert result.error == "registry unavailable"
    assert result.data.interfaces == []
    remote.finish.assert_called_once_with()


def test_empty_registry_interfaces_is_negative(monkeypatch):
    remote = Mock()
    monkeypatch.setattr(module_code, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(module_code.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    monkeypatch.setattr(module_code.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "base"}))
    monkeypatch.setattr(module_code.rrp, "hBaseRegQueryInfoKey", Mock(return_value={"lpcSubKeys": 0}))
    close = Mock()
    monkeypatch.setattr(module_code.rrp, "hBaseRegCloseKey", close)
    result = module_code.NXCModule().on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=Mock(), host="offline.invalid"))
    assert result.status is ResultStatus.NEGATIVE
    assert close.call_count == 2
    remote.finish.assert_called_once_with()
