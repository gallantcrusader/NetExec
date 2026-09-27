"""FTP listing and content with mocked transfers."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("failure", [False, True])
def test_ftp_listing_restores_directory_and_retains_partial_lines(failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ftp.py")
    conn = Mock()
    conn.pwd.return_value = "/home"

    def listing(command, callback):
        callback("-rw-r--r-- 1 owner group 12 Jan 1 00:00 file.txt")
        if failure:
            raise protocol.error_temp("450 listing interrupted")

    conn.retrlines.side_effect = listing
    fake = SimpleNamespace(args=SimpleNamespace(ls="/public"), conn=conn, logger=Mock(), host="offline.invalid", playbook_mode=True)
    result = protocol.ftp.ls(fake)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert len(result.data.lines) == 1
    assert [call.args[0] for call in conn.cwd.call_args_list] == ["/public", "/home"]
    conn.close.assert_not_called()


@pytest.mark.parametrize("content", [b"", b"hello\n", b"\xff\x00"])
@pytest.mark.parametrize("failure", [False, True])
def test_ftp_content_preserves_binary_and_partial_data(content, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ftp.py")
    conn = Mock(encoding="utf-8")

    def retrieve(command, callback):
        callback(content)
        if failure:
            raise protocol.error_temp("450 interrupted")

    conn.retrbinary.side_effect = retrieve
    fake = SimpleNamespace(args=SimpleNamespace(cat="/file"), conn=conn, logger=Mock(), host="offline.invalid", playbook_mode=True)
    result = protocol.ftp.cat(fake)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.content == content
    assert result.to_dict()["data"]["content"]["encoding"] == "base64"
    conn.close.assert_not_called()


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
def test_ftp_download_artifact_and_partial_transfer(tmp_path, monkeypatch, failure, explicit):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ftp.py")
    monkeypatch.setattr(protocol, "NXC_PATH", tmp_path)
    conn = Mock()

    def retrieve(command, callback):
        assert command == "RETR /remote/file.bin"
        callback(b"\x00\xffdata")
        if failure:
            raise protocol.error_temp("450 interrupted")

    conn.retrbinary.side_effect = retrieve
    output = tmp_path / "chosen.bin" if explicit else None
    fake = SimpleNamespace(args=SimpleNamespace(get_output=output), conn=conn, logger=Mock(), host="offline.invalid", playbook_mode=True)
    result = protocol.ftp.get_file(fake, "/remote/file.bin")
    expected = output or tmp_path / "downloads" / "ftp" / "offline.invalid" / "file.bin"
    assert result.data.local_path == expected
    assert expected.read_bytes() == b"\x00\xffdata"
    assert result.data.bytes_transferred == 6
    assert result.data.completed is not failure
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.artifacts[0].kind == ("partial_download" if failure else "download")
    conn.close.assert_not_called()


@pytest.mark.parametrize("failure", [False, True])
def test_ftp_upload_passes_file_object_and_reports_bytes(tmp_path, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ftp.py")
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    conn = Mock()

    def store(command, file, callback):
        assert command == "STOR /remote/file"
        assert file.read() == b"data"
        callback(b"data")
        if failure:
            raise protocol.error_temp("450 interrupted")

    conn.storbinary.side_effect = store
    fake = SimpleNamespace(conn=conn, logger=Mock(), host="offline.invalid", playbook_mode=True)
    result = protocol.ftp.put_file(fake, source, "/remote/file")
    assert result.data.bytes_transferred == 4
    assert result.data.completed is not failure
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.artifacts == []
    conn.size.assert_not_called()
    conn.close.assert_not_called()
