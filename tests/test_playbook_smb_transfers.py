"""SMB file transfers exercised with local files and a mock connection."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


def session(action, pairs):
    return SimpleNamespace(host="offline.invalid", hostname="OFFLINE", logger=Mock(), conn=Mock(), args=SimpleNamespace(share="C$", append_host=False, **{action: pairs}))


@pytest.mark.parametrize("payload", [b"", b"\x00binary\xff"])
def test_download_exact_bytes_and_artifact(tmp_path, payload):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    dest = tmp_path / "file.bin"
    fake = session("get_file", [[r"\remote.bin", str(dest)]])
    fake.conn.getFile.side_effect = lambda share, path, callback, **kwargs: callback(payload)
    result = protocol.smb.transfer_files(fake, "get_file")
    assert result.status is ResultStatus.SUCCESS
    assert dest.read_bytes() == payload
    assert result.data.files[0].bytes_transferred == len(payload)
    assert result.data.files[0].completed
    assert result.artifacts[0].path == dest
    fake.conn.close.assert_not_called()


def test_partial_download_stops_batch_and_retains_artifact(tmp_path):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    dest = tmp_path / "partial.bin"
    fake = session("get_file", [["one", str(dest)], ["two", str(tmp_path / "two")]])

    def receive(share, path, callback, **kwargs):
        callback(b"partial")
        raise RuntimeError("connection lost")

    fake.conn.getFile.side_effect = receive
    result = protocol.smb.transfer_files(fake, "get_file")
    assert result.status is ResultStatus.FAILED
    assert result.error == "connection lost"
    assert len(result.data.files) == 1
    assert result.data.files[0].bytes_transferred == 7
    assert not result.data.files[0].completed
    assert result.artifacts[0].kind == "partial_download"
    assert dest.read_bytes() == b"partial"
    fake.conn.getFile.assert_called_once()


def test_sharing_retry_replaces_partial_download(tmp_path):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = session("get_file", [["remote", str(tmp_path / "file")]])
    calls = []

    def receive(share, path, callback, **kwargs):
        calls.append(kwargs["shareAccessMode"])
        if len(calls) == 1:
            callback(b"old partial contents")
            raise protocol.SessionError(0xC0000043)
        callback(b"new")

    fake.conn.getFile.side_effect = receive
    result = protocol.smb.transfer_files(fake, "get_file")
    assert result.status is ResultStatus.SUCCESS
    assert (tmp_path / "file").read_bytes() == b"new"
    assert result.data.files[0].bytes_transferred == 3
    assert calls == [protocol.FILE_READ_DATA, protocol.FILE_READ_DATA | protocol.FILE_WRITE_DATA]


def test_upload_and_append_host_download_paths(tmp_path):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    source = tmp_path / "source.bin"
    source.write_bytes(b"abc")
    fake = session("put_file", [[str(source), r"\remote.bin"]])
    received = []
    fake.conn.putFile.side_effect = lambda share, path, callback: received.append(callback(1024))
    result = protocol.smb.transfer_files(fake, "put_file")
    assert result.status is ResultStatus.SUCCESS
    assert received == [b"abc"]
    assert result.data.files[0].bytes_transferred == 3
    assert result.artifacts == []
    fake = session("get_file", [[r"\nested\remote.bin", str(tmp_path / "dest.bin")]])
    fake.args.append_host = True
    result = protocol.smb.transfer_files(fake, "get_file")
    assert result.artifacts[0].path == tmp_path / "OFFLINE-dest.bin"
    assert result.artifacts[0].path.exists()


def test_append_host_single_download_keeps_requested_directory(tmp_path):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    dest_dir = tmp_path / "requested"
    dest_dir.mkdir()
    fake = session("get_file", [])
    fake.args.append_host = True
    fake.conn.getFile.side_effect = lambda share, path, callback, **kwargs: callback(b"payload")
    fake.download_file = lambda share, path, callback: protocol.smb.download_file(fake, share, path, callback)

    protocol.smb.get_file_single(fake, r"\nested\remote.bin", str(dest_dir / "chosen.bin"), silent=True)

    assert (dest_dir / "OFFLINE-chosen.bin").read_bytes() == b"payload"


def test_access_denied_does_not_retry_with_write_access(tmp_path):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = session("get_file", [["remote", str(tmp_path / "file")]])
    fake.conn.getFile.side_effect = protocol.SessionError(0xC0000022)
    result = protocol.smb.transfer_files(fake, "get_file")
    assert result.status is ResultStatus.FAILED
    assert "STATUS_ACCESS_DENIED" in result.error
    fake.conn.getFile.assert_called_once()


def test_upload_missing_file_never_contacts_remote(tmp_path):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = session("put_file", [[str(tmp_path / "missing"), "remote"]])
    result = protocol.smb.transfer_files(fake, "put_file")
    assert result.status is ResultStatus.FAILED
    assert not result.data.files[0].completed
    assert result.data.files[0].bytes_transferred == 0
    assert result.artifacts == []
    fake.conn.putFile.assert_not_called()


def test_download_missing_parent_has_no_artifact(tmp_path):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = session("get_file", [["remote", str(tmp_path / "missing" / "file")]])
    result = protocol.smb.transfer_files(fake, "get_file")
    assert result.status is ResultStatus.FAILED
    assert result.artifacts == []
    fake.conn.getFile.assert_not_called()
