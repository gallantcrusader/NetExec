"""Offline WinRM command records."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


def command_connection(protocol, response, shell):
    conn = Mock()
    if shell == "cmd":
        conn.execute_cmd.return_value = response
    else:
        conn.execute_ps.return_value = response
    fake = SimpleNamespace(conn=conn, host="offline.invalid", args=SimpleNamespace(codec="utf-8", no_output=True, execute="example-command", ps_execute="example-command"), logger=Mock(), playbook_mode=True)
    fake.execute_result = lambda *args: protocol.winrm.execute_result(fake, *args)
    return fake


@pytest.mark.parametrize("status", [0, 5])
def test_winrm_cmd_retains_both_streams_and_status(status):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/winrm.py")
    fake = command_connection(protocol, ("output", "stderr", status), "cmd")
    result = protocol.winrm.execute(fake)
    assert result.data.stdout == "output"
    assert result.data.stderr == "stderr"
    assert result.data.exit_status == status
    assert result.status is (ResultStatus.FAILED if status else ResultStatus.SUCCESS)
    fake.logger.highlight.assert_not_called()


@pytest.mark.parametrize(("had_errors", "messages"), [(False, []), (True, []), (False, ["nonterminating error"])])
def test_powershell_has_error_flag_not_numeric_exit_code(had_errors, messages):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/winrm.py")
    streams = SimpleNamespace(debug=[], verbose=[], information=["info"], progress=[], warning=[], error=messages)
    fake = command_connection(protocol, ("output", streams, had_errors), "powershell")
    result = protocol.winrm.ps_execute(fake)
    assert result.action == "ps_execute"
    assert result.data.exit_status is None
    assert result.data.had_errors is had_errors
    assert result.data.streams["error"] == messages
    assert result.status is (ResultStatus.FAILED if had_errors or messages else ResultStatus.SUCCESS)


def test_winrm_fallback_preserves_requested_action_and_actual_shell():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/winrm.py")
    streams = SimpleNamespace(**{name: [] for name in ("debug", "verbose", "information", "progress", "warning", "error")})
    fake = command_connection(protocol, ("fallback output", streams, False), "powershell")
    denied = RuntimeError("access denied")
    denied.code = 5
    fake.conn.execute_cmd.side_effect = denied
    result = protocol.winrm.execute(fake)
    assert result.action == "execute"
    assert result.data.shell == "powershell"
    assert result.data.stdout == "fallback output"
    assert result.status is ResultStatus.SUCCESS
    fake.conn.execute_cmd.assert_called_once()
    fake.conn.execute_ps.assert_called_once()


@pytest.mark.parametrize("action", ["get_file", "put_file"])
@pytest.mark.parametrize("failure", [False, True])
def test_winrm_file_actions_return_final_paths(tmp_path, action, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/winrm.py")
    local = tmp_path / "file.txt"
    remote = "C:/Temp/file.txt"
    args = SimpleNamespace(get_file=[remote, str(tmp_path) + "/"], put_file=[local, "C:/Temp/"])
    conn = Mock()
    if failure:
        getattr(conn, "fetch" if action == "get_file" else "copy").side_effect = OSError("transfer denied")
    fake = SimpleNamespace(args=args, conn=conn, logger=Mock(), host="offline.invalid", playbook_mode=True)
    result = getattr(protocol.winrm, action)(fake)
    assert result.data.local_path == local
    assert result.data.remote_path == remote
    assert result.data.completed is not failure
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert len(result.artifacts) == (1 if action == "get_file" and not failure else 0)
    if failure:
        assert result.error == "transfer denied"
    conn.close.assert_not_called()


def test_winrm_directory_returns_command_outcome():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/winrm.py")
    fake = command_connection(protocol, ("directory output", "", 0), "cmd")
    fake.args.dir = "C:/Temp"
    result = protocol.winrm.dir(fake)
    assert result.action == "dir"
    assert result.data.stdout == "directory output"
    assert result.data.command == "dir C:/Temp"
