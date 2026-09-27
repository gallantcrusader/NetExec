"""Offline OXID binding enumeration and cleanup."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.dcerpc.v5.dcomrt import STRINGBINDING

import nxc.modules.ioxidresolver as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("different", [False, True])
@pytest.mark.parametrize("protocol", ["smb", "wmi"])
def test_oxid_records_and_canonical_filter(monkeypatch, different, protocol):
    rpc = Mock()
    monkeypatch.setattr(code, "NXCRPCConnection", Mock(return_value=Mock(connect=Mock(return_value=rpc))))
    rows = [{"aNetworkAddr": "2001:0db8::1\x00", "wTowerId": 7}, {"aNetworkAddr": "192.0.2.1\x00", "wTowerId": 7}, {"aNetworkAddr": "192.0.2.1", "wTowerId": 7}, {"aNetworkAddr": "HOST\x00", "wTowerId": 15}]
    actual = []
    for row in rows:
        binding = STRINGBINDING()
        binding["aNetworkAddr"] = row["aNetworkAddr"]
        binding["wTowerId"] = row["wTowerId"]
        actual.append(binding)
    monkeypatch.setattr(code, "IObjectExporter", Mock(return_value=Mock(ServerAlive2=Mock(return_value=actual))))
    module = code.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"DIFFERENT": str(different)})
    result = module.on_login(context, SimpleNamespace(host="2001:db8::1", args=SimpleNamespace(protocol=protocol)))
    validate_module_result(module, result, protocol, "2001:db8::1")
    assert result.status is ResultStatus.SUCCESS
    assert result.data.addresses == (["192.0.2.1"] if different else ["2001:db8::1", "192.0.2.1"])
    assert len(result.data.bindings) == 4
    assert result.data.bindings[-1] == {"network_address": "HOST", "tower_id": 15, "ip_address": None}
    rpc.disconnect.assert_called_once_with()


@pytest.mark.parametrize("failure", ["query", "cleanup"])
def test_oxid_failure_retains_records(monkeypatch, failure):
    rpc = Mock()
    monkeypatch.setattr(code, "NXCRPCConnection", Mock(return_value=Mock(connect=Mock(return_value=rpc))))

    def rows():
        yield {"aNetworkAddr": "192.0.2.1\x00", "wTowerId": 7}
        if failure == "query":
            raise RuntimeError("query failed")

    monkeypatch.setattr(code, "IObjectExporter", Mock(return_value=Mock(ServerAlive2=Mock(return_value=rows()))))
    if failure == "cleanup":
        rpc.disconnect.side_effect = RuntimeError("cleanup failed")
    module = code.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {})
    result = module.on_login(context, SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol="smb")))
    assert result.status is ResultStatus.FAILED
    assert result.data.addresses == ["192.0.2.1"]
    assert f"{failure} failed" in result.error
    rpc.disconnect.assert_called_once_with()
