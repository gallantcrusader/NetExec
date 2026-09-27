"""Offline shortcuts retain provenance, original bytes and partial failures."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules import recent_files as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def entry(name, directory=False):
    return SimpleNamespace(get_longname=lambda: name, is_directory=lambda: directory)


@pytest.mark.parametrize("failure", [None, "missing", "denied", "read", "parse", "no_target"])
def test_recent_shortcuts(monkeypatch, failure):
    raw = b"shortcut bytes"
    parser = Mock(return_value=SimpleNamespace(path=None if failure == "no_target" else " C:\\file with spaces "))
    if failure == "parse":
        parser.side_effect = ValueError("invalid shortcut")
    monkeypatch.setattr(code.pylnk3, "parse", parser)
    smb = Mock()
    listing = code.SessionError(code.STATUS_OBJECT_NAME_NOT_FOUND) if failure == "missing" else code.SessionError(0xC0000022) if failure == "denied" else [entry("file.lnk"), entry("directory", True)]
    smb.listPath.side_effect = [[entry("alice", True), entry("bob", True), entry("Public", True)], listing, listing]

    def download(share, path, callback):
        callback(raw)
        if failure == "read":
            raise RuntimeError("partial download")

    smb.getFile.side_effect = download
    module = code.NXCModule()
    connection = SimpleNamespace(host="offline.invalid", conn=smb)
    result = module.on_admin_login(SimpleNamespace(log=Mock()), connection)
    validate_module_result(module, result, "smb", connection.host)
    failed = failure in ("denied", "read", "parse")
    assert result.status is (ResultStatus.FAILED if failed else ResultStatus.NEGATIVE if failure == "missing" else ResultStatus.SUCCESS)
    assert result.data.queried_users == (["alice"] if failed else ["alice", "bob"])
    if failure in ("missing", "denied"):
        assert result.data.shortcuts == []
    else:
        assert len(result.data.shortcuts) == (1 if failed else 2)
        first = result.data.shortcuts[0]
        assert first["content"] == raw
        assert first["downloaded"] is (failure != "read")
        assert first["parsed"] is (failure not in ("read", "parse"))
        if not failed:
            assert [record["user"] for record in result.data.shortcuts] == ["alice", "bob"]
    assert result.data.paths == ([" C:\\file with spaces "] if failure is None else [])
    smb.close.assert_not_called()
