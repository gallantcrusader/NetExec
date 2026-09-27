"""Offline history exports, binary preservation, absence, and partial reads."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules import powershell_history as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def entry(name, directory=False):
    return SimpleNamespace(get_longname=lambda: name, is_directory=lambda: directory)


@pytest.mark.parametrize("export", ["false", "true"])
@pytest.mark.parametrize("failure", [None, "missing", "denied", "read", "export"])
def test_history_results(monkeypatch, tmp_path, export, failure):
    root = tmp_path / "output"
    if failure == "export":
        root.write_text("file")
    monkeypatch.setattr(code, "NXC_PATH", root)
    module = code.NXCModule()
    module.options(None, {"EXPORT": export})
    smb = Mock()
    histories = [entry("ConsoleHost_history.txt"), entry("VSCode_history.txt"), entry("subdir", True)]
    listing = code.SessionError(code.STATUS_OBJECT_PATH_NOT_FOUND) if failure == "missing" else code.SessionError(0xC0000022) if failure == "denied" else histories
    smb.listPath.side_effect = [[entry("alice", True), entry("Public", True)], listing]
    raw = b"\xef\xbb\xbfpassword example\ninvalid: \xff\n"

    def download(share, path, callback):
        assert share == "C$"
        callback(raw)
        if failure == "read":
            raise RuntimeError("read interrupted")

    smb.getFile.side_effect = download
    conn = SimpleNamespace(host="offline.invalid", conn=smb)
    result = module.on_admin_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "smb", conn.host)
    failed = failure in ("denied", "read") or (failure == "export" and export == "true")
    assert result.status is (ResultStatus.FAILED if failed else ResultStatus.NEGATIVE if failure == "missing" else ResultStatus.SUCCESS)
    if failure in ("missing", "denied"):
        assert result.data.files == []
    else:
        assert len(result.data.files) == (1 if failed else 2)
        first = result.data.files[0]
        assert first["content"] == raw
        assert first["text"].startswith("password")
        assert "\ufffd" in first["text"]
        assert first["complete"] is (failure != "read")
        if failure != "read":
            assert "PASSWORD" in first["keywords"]
        if export == "true" and not failed:
            assert len(result.artifacts) == 2
            assert result.artifacts[0].path != result.artifacts[1].path
            assert all(artifact.path.read_bytes() == raw for artifact in result.artifacts)
    if export == "false" or failed or failure == "missing":
        assert result.artifacts == []
    assert result.data.queried_users == ["alice"]
    smb.close.assert_not_called()
