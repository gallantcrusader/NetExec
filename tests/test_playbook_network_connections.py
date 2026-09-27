"""Offline WMI network adapter records and export errors."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import nxc.modules.get_netconnections as code
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("protocol", ["smb", "wmi"])
@pytest.mark.parametrize("failure", [None, "query", "file"])
def test_network_records_and_artifacts(monkeypatch, tmp_path, protocol, failure):
    root = tmp_path / "output"
    if failure == "file":
        root.write_text("file")
    monkeypatch.setattr(code, "NXC_PATH", root)
    cards = [{"IPAddress": {"value": ["192.0.2.1", "2001:db8::1"], "type": 8}, "DNSDomainSuffixSearchOrder": {"value": None}}]
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol=protocol), last_wmi_error="partial query" if failure == "query" else None, wmi_query=Mock(return_value=cards))
    module = code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, protocol, conn.host)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.adapters == cards
    if failure == "file":
        assert not result.artifacts
    else:
        assert json.loads(result.artifacts[0].path.read_text()) == [cards]


def test_explicit_wmi_query_retains_login_and_exposes_error():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/wmi.py")
    login = Mock()
    enumerator = login.NTLMLogin.return_value.ExecQuery.return_value
    obj = Mock()
    obj.getProperties.return_value = {"IPAddress": {"value": ["192.0.2.1"]}}
    enumerator.Next.side_effect = [[obj], RuntimeError("partial query")]
    fake = SimpleNamespace(args=SimpleNamespace(wmi_namespace="root/cimv2"), playbook_mode=True, admin_privs=True, iWbemLevel1Login=login, host="offline.invalid", logger=Mock())
    fake.query_result = lambda query=None, namespace=None: protocol.wmi.query_result(fake, query, namespace)
    records = protocol.wmi.wmi_query(fake, "SELECT IPAddress FROM Example")
    assert records == [{"IPAddress": {"value": ["192.0.2.1"]}}]
    assert fake.last_wmi_error == "partial query"
    login.RemRelease.assert_not_called()
    obj.RemRelease.assert_called_once_with()
    enumerator.RemRelease.assert_called_once_with()
