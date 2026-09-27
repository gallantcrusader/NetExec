"""Offline WMI query records, partial errors, and resource ownership."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("end", ["empty", "S_FALSE", "failure"])
def test_wmi_query_retains_records_and_reuses_login(end):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/wmi.py")
    obj = Mock()
    obj.getProperties.return_value = {"Name": {"value": "example", "type": 8}}
    enumerator = Mock()
    enumerator.Next.side_effect = [[obj], [] if end == "empty" else RuntimeError("S_FALSE" if end == "S_FALSE" else "access denied")]
    services = Mock()
    services.ExecQuery.return_value = enumerator
    login = Mock()
    login.NTLMLogin.return_value = services
    fake = SimpleNamespace(args=SimpleNamespace(wmi_query="SELECT Name FROM Example", wmi_namespace="root/cimv2"), iWbemLevel1Login=login, host="offline.invalid", admin_privs=True, logger=Mock(), playbook_mode=True)
    fake.query_result = lambda: protocol.wmi.query_result(fake)
    result = protocol.wmi.wmi_query(fake)
    assert result.data.records == [{"Name": {"value": "example", "type": 8}}]
    assert result.status is (ResultStatus.FAILED if end == "failure" else ResultStatus.SUCCESS)
    assert result.data.namespace == "root/cimv2"
    obj.RemRelease.assert_called_once()
    enumerator.RemRelease.assert_called_once()
    services.RemRelease.assert_called_once()
    login.RemRelease.assert_not_called()


def test_wmi_empty_query_is_negative():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/wmi.py")
    login = Mock()
    login.NTLMLogin.return_value.ExecQuery.return_value.Next.return_value = []
    fake = SimpleNamespace(args=SimpleNamespace(wmi_query="SELECT Name FROM Example", wmi_namespace="root/cimv2"), iWbemLevel1Login=login, host="offline.invalid", admin_privs=True, logger=Mock())
    assert protocol.wmi.query_result(fake).status is ResultStatus.NEGATIVE


@pytest.mark.parametrize("ending", [None, "S_FALSE", "callback denied", "cleanup denied"])
def test_wmi_callback_preserves_records_and_cleans_owned_resources(ending):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/wmi.py")
    login = Mock()
    services = login.NTLMLogin.return_value
    enumerator = services.ExecQuery.return_value
    if ending == "cleanup denied":
        enumerator.RemRelease.side_effect = RuntimeError(ending)
    fake = SimpleNamespace(args=SimpleNamespace(wmi_query="SELECT Name FROM Example", wmi_namespace="root/cimv2"), iWbemLevel1Login=login, host="offline.invalid", admin_privs=True, logger=Mock(), playbook_mode=True)
    fake.query_result = lambda query=None, namespace=None, callback=None: protocol.wmi.query_result(fake, query, namespace, callback)

    def callback(received, records):
        assert received is enumerator
        records.append({"Name": {"value": "partial"}})
        if ending in ("S_FALSE", "callback denied"):
            raise RuntimeError(ending)

    records = protocol.wmi.wmi_query(fake, "SELECT Name FROM Example", callback_func=callback)
    assert records == [{"Name": {"value": "partial"}}]
    assert bool(fake.last_wmi_error) is (ending in ("callback denied", "cleanup denied"))
    enumerator.RemRelease.assert_called_once_with()
    services.RemRelease.assert_called_once_with()
    login.RemRelease.assert_not_called()
