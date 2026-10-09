"""Offline SMB process filtering and terminal server resource ownership."""

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("filter_value", [True, "EXAMPLE", "missing"])
@pytest.mark.parametrize("failure", [None, "enumeration", "cleanup"])
def test_process_records_and_partial_failures(monkeypatch, filter_value, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    legacy = Mock()
    legacy.hRpcWinStationOpenServer.return_value = "handle"
    legacy.hRpcWinStationCloseServer.return_value = {"ErrorCode": failure != "cleanup", "pResult": 5}

    def processes():
        process = Mock()
        image_name = Mock()
        image_name.getValue.return_value = "Example.exe"
        process.getProcessInfo.return_value = {
            "ImageName": image_name,
            "UniqueProcessId": 123,
            "SessionId": 2,
            "WorkingSetSize": 4567,
        }
        process.getSid.return_value = "S-1-5-18"
        yield process
        if failure == "enumeration":
            raise RuntimeError("enumeration denied")

    legacy.hRpcWinStationGetAllProcesses.return_value = processes()
    manager = MagicMock()
    manager.__enter__.return_value = legacy
    monkeypatch.setattr(protocol.TSTS, "LegacyAPI", Mock(return_value=manager))
    fake = SimpleNamespace(admin_privs=True, args=SimpleNamespace(tasklist=filter_value), conn=Mock(), host="offline.invalid", kerberos=False, logger=Mock(), playbook_mode=True)
    result = protocol.smb.tasklist(fake)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.NEGATIVE if filter_value == "missing" else ResultStatus.SUCCESS)
    assert len(result.data.processes) == (0 if filter_value == "missing" else 1)
    if result.data.processes:
        assert result.data.processes[0].working_set_bytes == 4567
        assert result.data.processes[0].pid == 123
    legacy.hRpcWinStationCloseServer.assert_called_once_with("handle")
    manager.__exit__.assert_called_once()
    fake.conn.close.assert_not_called()
