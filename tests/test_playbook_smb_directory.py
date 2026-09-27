"""Offline SMB listing records for file-selection branches."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus, json_value


def entry(name, directory=False, readonly=False, size=0):
    return Mock(get_longname=Mock(return_value=name), is_directory=Mock(return_value=directory), is_readonly=Mock(return_value=readonly), get_filesize=Mock(return_value=size), get_mtime_epoch=Mock(return_value=1234567890.5))


def test_directory_records_preserve_metadata_and_paths():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(dir=r"\Folder", share="DATA"), conn=Mock(), logger=Mock(), playbook_mode=True)
    fake.conn.listPath.return_value = [entry("café.txt", readonly=True, size=42), entry("child", directory=True)]
    result = protocol.smb.dir(fake)
    assert result.status is ResultStatus.SUCCESS
    assert json_value(result.data) == {"share": "DATA", "path": r"\Folder", "entries": [
        {"name": "café.txt", "path": r"\Folder\café.txt", "is_directory": False, "readonly": True, "size": 42, "modified_epoch": 1234567890.5},
        {"name": "child", "path": r"\Folder\child", "is_directory": True, "readonly": False, "size": 0, "modified_epoch": 1234567890.5},
    ]}
    fake.conn.listPath.assert_called_once_with("DATA", r"\Folder\*")
    fake.conn.close.assert_not_called()


@pytest.mark.parametrize("failure", [None, "rpc", "record"])
def test_directory_empty_and_failed_results(failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(dir="", share="C$"), conn=Mock(), logger=Mock(), playbook_mode=True)
    fake.conn.listPath.return_value = []
    if failure == "rpc":
        fake.conn.listPath.side_effect = protocol.SessionError(0xC0000022)
    elif failure == "record":
        broken = entry("broken")
        broken.get_filesize.side_effect = ValueError("bad size")
        fake.conn.listPath.return_value = [entry("valid"), broken]
    result = protocol.smb.dir(fake)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.NEGATIVE)
    assert len(result.data.entries) == (1 if failure == "record" else 0)
    if failure == "rpc":
        assert "STATUS_ACCESS_DENIED" in result.error
    elif failure == "record":
        assert result.error == "bad size"
