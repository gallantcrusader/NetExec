"""Offline SMB WMI query records, callbacks, and owned resource cleanup."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("failure", [None, "enumeration", "binding", "cleanup"])
def test_smb_wmi_query_retains_records_and_releases_resources(monkeypatch, failure, explicit):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    obj = Mock()
    obj.getProperties.return_value = {"Name": {"value": "sample"}}
    enumerator = Mock()
    enumerator.Next.side_effect = [[obj], RuntimeError("query failed" if failure == "enumeration" else "S_FALSE")]
    services = Mock(ExecQuery=Mock(return_value=enumerator))
    login = Mock(NTLMLogin=Mock(return_value=services))
    dcom = Mock()
    if failure == "cleanup":
        dcom.disconnect.side_effect = RuntimeError("close failed")
    monkeypatch.setattr(protocol, "DCOMConnection", Mock(return_value=dcom))
    monkeypatch.setattr(protocol, "IWbemLevel1Login", Mock(return_value=login))
    monkeypatch.setattr(protocol, "dcom_FirewallChecker", Mock(return_value=(failure != "binding", "binding")))
    fake = SimpleNamespace(admin_privs=True, playbook_mode=True, args=SimpleNamespace(wmi_query="SELECT Name FROM Example", wmi_namespace="root/cimv2", dcom_timeout=5), host="offline.invalid", remoteName="offline.invalid", username="alice", password="example", domain="EXAMPLE", lmhash="", nthash="", kerberos=False, kdcHost=None, aesKey=None, logger=Mock())
    result = protocol.smb.wmi_query(fake, "SELECT Name FROM Example") if explicit else protocol.smb.wmi_query(fake)
    records = result if explicit else result.data.records
    if not explicit:
        assert result.status is (ResultStatus.SUCCESS if failure is None else ResultStatus.FAILED)
        assert fake.last_wmi_error == result.error
    assert records == ([] if failure == "binding" else [{"Name": {"value": "sample"}}])
    login.RemRelease.assert_called_once_with()
    dcom.disconnect.assert_called_once_with()
    if failure != "binding":
        obj.RemRelease.assert_called_once_with()
        services.RemRelease.assert_called_once_with()
        enumerator.RemRelease.assert_called_once_with()
    else:
        login.NTLMLogin.assert_not_called()
