"""Offline rclone fields, section provenance and read/decode errors."""

import base64
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from Crypto.Cipher import AES

from nxc.modules import rclone as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def obscured(value):
    key = bytes.fromhex("9c935b48730a554d6bfd7c63c886a92bd390198eb8128afbf4de162b8b95f638")
    iv = bytes(range(16))
    return base64.urlsafe_b64encode(iv + AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv).encrypt(value.encode())).decode().rstrip("=")


@pytest.mark.parametrize("scenario", ["normal", "missing", "denied", "partial", "encrypted", "decode", "syntax"])
def test_rclone_results(scenario):
    password = obscured("secret é")
    raw = f"# comment\n[one]\ntype = sftp\npass = {password}\n[two]\ntoken = a=b\npassword = {password}\n".encode()
    if scenario == "encrypted":
        raw = b"# encrypted\nRCLONE_ENCRYPT_V0:\nopaque-base64\n"
    elif scenario == "decode":
        raw = b"[one]\ntype=sftp\npass=bad\n"
    elif scenario == "syntax":
        raw = b"[one]\ntype=sftp\ninvalid line\n"
    smb = Mock()
    smb.listPath.return_value = [SimpleNamespace(get_longname=lambda: "alice", is_directory=lambda: True)]

    def download(share, path, callback):
        assert share == "C$"
        assert path == "\\Users\\alice\\AppData\\Roaming\\rclone\\rclone.conf"
        if scenario == "missing":
            raise code.SessionError(code.STATUS_OBJECT_NAME_NOT_FOUND)
        if scenario == "denied":
            raise code.SessionError(0xC0000022)
        callback(raw)
        if scenario == "partial":
            raise RuntimeError("read interrupted")

    smb.getFile.side_effect = download
    module = code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(host="offline.invalid", conn=smb))
    validate_module_result(module, result, "smb", "offline.invalid")
    assert result.data.queried_users == ["alice"]
    expected = {"normal": ResultStatus.SUCCESS, "missing": ResultStatus.NEGATIVE, "encrypted": ResultStatus.SKIPPED}
    assert result.status is expected.get(scenario, ResultStatus.FAILED)
    if scenario == "missing":
        assert result.data.files == []
    else:
        record = result.data.files[0]
        assert record["content"] == (b"" if scenario == "denied" else raw)
        assert record["complete"] is (scenario not in ("denied", "partial"))
        if scenario == "normal":
            assert [entry["section"] for entry in record["entries"]] == ["one", "one", "two", "two"]
            assert record["entries"][1]["plaintext"] == "secret é"
            assert record["entries"][1]["value"] == password
            assert record["entries"][2]["value"] == "a=b"
        elif scenario == "decode":
            assert record["entries"][0]["value"] == "sftp"
            assert record["entries"][1]["error"]
        elif scenario == "encrypted":
            assert record["encrypted"]
            assert record["entries"] == []
    smb.close.assert_not_called()
