"""Offline SSH command outputs and failures."""

from threading import Barrier
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("status", [0, 7, -1])
@pytest.mark.parametrize("no_output", [False, True])
def test_ssh_command_drains_both_streams_and_reports_status(status, no_output):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ssh.py")
    barrier = Barrier(2, timeout=2)

    def read(value):
        barrier.wait()
        return value

    stdin = Mock()
    stdout = Mock()
    stderr = Mock()
    stdout.read.side_effect = lambda: read(b"out\xff\n")
    stderr.read.side_effect = lambda: read(b"err\n")
    stdout.channel.recv_exit_status.return_value = status
    conn = Mock()
    conn.exec_command.return_value = (stdin, stdout, stderr)
    fake = SimpleNamespace(args=SimpleNamespace(execute="example-command", ssh_timeout=3, no_output=no_output, codec="utf-8"), conn=conn, logger=Mock(), host="offline.invalid", playbook_mode=True)
    fake.execute_result = lambda: protocol.ssh.execute_result(fake)
    result = protocol.ssh.execute(fake)
    assert result.data.stdout == b"out\xff\n"
    assert result.data.stderr == b"err\n"
    assert result.data.exit_status == (None if status == -1 else status)
    assert result.status is (ResultStatus.SUCCESS if status == 0 else ResultStatus.FAILED)
    conn.exec_command.assert_called_once_with("example-command", timeout=3)
    assert fake.logger.highlight.call_count == (0 if no_output else 2)
    stdout.close.assert_called_once()
    stderr.close.assert_called_once()
    conn.close.assert_not_called()
    assert result.to_dict()["data"]["stdout"]["encoding"] == "base64"


def test_ssh_connection_failure_returns_unknown_exit_status():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ssh.py")
    fake = SimpleNamespace(args=SimpleNamespace(execute="example-command", ssh_timeout=3), conn=Mock(), logger=Mock(), host="offline.invalid")
    fake.conn.exec_command.side_effect = OSError("connection lost")
    result = protocol.ssh.execute_result(fake)
    assert result.status is ResultStatus.FAILED
    assert result.data.exit_status is None
    assert result.error == "connection lost"


@pytest.mark.parametrize("action", ["get_file", "put_file"])
@pytest.mark.parametrize("failure", [None, "transfer", "close"])
def test_sftp_results_and_cleanup(action, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ssh.py")
    sftp = Mock()
    if failure == "transfer":
        getattr(sftp, "get" if action == "get_file" else "put").side_effect = [None, OSError("transfer failed")]
    if failure == "close":
        sftp.close.side_effect = OSError("close failed")
    fake = SimpleNamespace(conn=Mock(), logger=Mock(), host="offline.invalid")
    fake.conn.open_sftp.return_value = sftp
    result = protocol.ssh.transfer_files(fake, action, [("first", "one"), ("second", "two"), ("third", "three")])
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.transfers[0].completed
    assert len(result.data.transfers) == (2 if failure == "transfer" else 3)
    if failure == "transfer":
        assert not result.data.transfers[1].completed
        assert result.data.transfers[1].error == "transfer failed"
    assert len(result.artifacts) == ((1 if failure == "transfer" else 3) if action == "get_file" else 0)
    sftp.close.assert_called_once()
    fake.conn.close.assert_not_called()
