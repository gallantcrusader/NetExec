"""Offline registry observations preserve raw values and partial failure."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("failure", [None, "absent", "denied", "cleanup", "startup"])
def test_winlogon_values_and_resource_lifetime(monkeypatch, failure):
    code = import_module("nxc.modules.reg-winlogon")
    remote = Mock()
    if failure == "startup":
        remote.enableRegistry.side_effect = RuntimeError("startup failed")
    factory = Mock(return_value=remote)
    monkeypatch.setattr(code, "RemoteOperations", factory)
    monkeypatch.setattr(code.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    monkeypatch.setattr(code.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "key"}))
    raw = ["1\x00", "EXAMPLE\x00", "alice\x00", "plain text\x00"]
    query = Mock(side_effect=[(code.rrp.REG_SZ, value) for value in raw])
    if failure == "absent":
        query.side_effect = code.rrp.DCERPCSessionError(error_code=2)
    elif failure == "denied":
        query.side_effect = [(code.rrp.REG_SZ, raw[0]), code.rrp.DCERPCSessionError(error_code=5)]
    monkeypatch.setattr(code.rrp, "hBaseRegQueryValue", query)
    close = Mock(side_effect=[RuntimeError("close failed"), None] if failure == "cleanup" else None)
    monkeypatch.setattr(code.rrp, "hBaseRegCloseKey", close)
    connection = SimpleNamespace(host="offline.invalid", conn=Mock())
    module = code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), connection)
    validate_module_result(module, result, "smb", connection.host)
    assert result.status is (ResultStatus.NEGATIVE if failure == "absent" else ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    if failure == "startup":
        assert result.data.queried_names == []
        assert result.data.values == {}
        close.assert_not_called()
    else:
        assert [call.args[1] for call in close.call_args_list] == ["key", "root"]
        assert result.data.queried_names == list(module.value_names[:2] if failure == "denied" else module.value_names)
        if failure == "absent":
            assert all(not value.present and value.error is None for value in result.data.values.values())
        elif failure == "denied":
            assert result.data.values["AutoAdminLogon"].value == raw[0]
            assert result.data.values["DefaultDomainName"].error
            assert "DefaultPassword" not in result.data.values
        else:
            assert [value.value for value in result.data.values.values()] == raw
            assert all(value.registry_type == code.rrp.REG_SZ for value in result.data.values.values())
    factory.assert_called_once_with(connection.conn, False)
    remote.finish.assert_called_once_with()
    connection.conn.close.assert_not_called()
