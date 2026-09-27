"""Offline Notepad++ backups retain case, invalid UTF-8 and read errors."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def entry(name, directory=False):
    return SimpleNamespace(get_longname=lambda: name, is_directory=lambda: directory)


@pytest.mark.parametrize("failure", [None, "missing", "denied", "read", "export"])
def test_backup_records_and_artifacts(monkeypatch, tmp_path, failure):
    code = import_module("nxc.modules.notepad++")
    root = tmp_path / "output"
    if failure == "export":
        root.write_text("file")
    monkeypatch.setattr(code, "NXC_PATH", root)
    module = code.NXCModule()
    smb = Mock()
    listing = [entry("New 1@timestamp"), entry("Code@timestamp"), entry("subdir", True)]
    if failure == "missing":
        listing = code.SessionError(code.STATUS_OBJECT_PATH_NOT_FOUND)
    elif failure == "denied":
        listing = code.SessionError(0xC0000022)
    smb.listPath.side_effect = [[entry("alice", True)], listing]
    raw = b"CaseSensitivePassword\r\nCODE\xff\n"

    def download(share, path, callback):
        assert "Notepad++\\backup\\" in path
        callback(raw)
        if failure == "read":
            raise RuntimeError("download failed")

    smb.getFile.side_effect = download
    conn = SimpleNamespace(host="offline.invalid", conn=smb)
    result = module.on_admin_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "smb", conn.host)
    assert result.status is (ResultStatus.NEGATIVE if failure == "missing" else ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    if failure in ("missing", "denied"):
        assert result.data.files == []
    else:
        assert result.data.files[0]["content"] == raw
        assert result.data.files[0]["text"].startswith("CaseSensitivePassword")
        assert result.data.files[0]["complete"] is (failure != "read")
    if not failure:
        assert len(result.artifacts) == 2
        assert result.artifacts[0].path != result.artifacts[1].path
        assert all(item.path.read_bytes() == raw for item in result.artifacts)
        assert all(item.kind == "notepad_backup" for item in result.artifacts)
    else:
        assert result.artifacts == []
    smb.close.assert_not_called()
