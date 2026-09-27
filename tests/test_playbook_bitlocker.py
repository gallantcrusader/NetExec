"""Offline BitLocker observations and shared WMI resource lifetime."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.modules.bitlocker import NXCModule
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("protocol", ["smb", "wmi"])
@pytest.mark.parametrize("failure", [None, "query", "empty"])
def test_bitlocker_observations(protocol, failure):
    records = [] if failure == "empty" else [{"MountPoint": "C:", "ProtectionStatus": 1, "EncryptionMethod": 7}, {"MountPoint": None, "ProtectionStatus": 2, "EncryptionMethod": 999}]
    error = "query failed" if failure == "query" else None
    wmi_records = [{("DriveLetter" if k == "MountPoint" else k): {"value": v} for k, v in record.items()} for record in records]
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol=protocol),
                           execute=Mock(return_value=json.dumps({"volumes": records, "error": error})),
                           query_result=Mock(return_value=SimpleNamespace(data=SimpleNamespace(records=wmi_records), error=error)))
    module = NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, protocol, conn.host)
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.NEGATIVE if failure == "empty" else ResultStatus.SUCCESS)
    if records:
        assert result.data.volumes[0]["protection_enabled"] is True
        assert result.data.volumes[1]["protection_enabled"] is None
        assert result.data.volumes[1]["encryption_method"] == 999
    if protocol == "wmi":
        conn.execute.assert_not_called()
        assert conn.query_result.call_args.kwargs["auth_level"] == 6
    else:
        conn.query_result.assert_not_called()


def test_missing_powershell_output_fails():
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol="smb"), execute=Mock(return_value=""))
    result = NXCModule().on_admin_login(SimpleNamespace(log=Mock()), conn)
    assert result.status is ResultStatus.FAILED
    assert result.data.output == ""


def test_encrypted_wmi_query_keeps_shared_login():
    code = ProtocolLoader().load_protocol("nxc/protocols/wmi.py")
    login = Mock()
    services = login.NTLMLogin.return_value
    enumerator = services.ExecQuery.return_value
    enumerator.Next.side_effect = RuntimeError("WBEM_S_FALSE")
    conn = SimpleNamespace(iWbemLevel1Login=login, args=SimpleNamespace(wmi_namespace="unused"), host="offline.invalid", logger=Mock())
    result = code.wmi.query_result(conn, "SELECT Example", "namespace", auth_level=6)
    assert result.status is ResultStatus.NEGATIVE
    services.get_dce_rpc.return_value.set_auth_level.assert_called_once_with(6)
    enumerator.RemRelease.assert_called_once_with()
    services.RemRelease.assert_called_once_with()
    login.RemRelease.assert_not_called()
