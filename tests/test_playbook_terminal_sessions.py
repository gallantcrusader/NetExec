"""Offline terminal session results; no remote connections."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus, json_value


@pytest.mark.parametrize(("username", "count"), [("", 2), ("ALICE", 1), ("missing", 0)])
def test_terminal_sessions_filter_and_serialize(username, count):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = SimpleNamespace(host="offline.invalid", logger=Mock(), args=SimpleNamespace(qwinsta=username), get_session_list=Mock(return_value={
        1: {"Username": "Alice", "Domain": "EXAMPLE", "state": "Active", "ConnectTime": datetime(2026, 1, 1)},
        2: {"Username": "Bob", "Domain": "EXAMPLE", "state": "Disconnected"},
    }), enumerate_sessions_info=Mock(return_value=[]))
    result = protocol.smb.qwinsta_result(fake)
    assert len(result.data.sessions) == count
    assert result.status is (ResultStatus.SUCCESS if count else ResultStatus.NEGATIVE)
    if count:
        assert result.data.sessions[0]["id"] == 1
        assert json_value(result.data)["sessions"][0]["ConnectTime"] == "2026-01-01T00:00:00"


@pytest.mark.parametrize("failure", ["details", "address", "listing"])
def test_terminal_sessions_keep_partial_records(failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = SimpleNamespace(host="offline.invalid", logger=Mock(), args=SimpleNamespace(qwinsta=""), get_session_list=Mock(return_value={1: {"Username": "Alice"}}), enumerate_sessions_info=Mock(return_value=[]))
    if failure == "listing":
        fake.get_session_list.side_effect = RuntimeError("listing denied")
    elif failure == "details":
        fake.enumerate_sessions_info.side_effect = RuntimeError("details denied")
    else:
        fake.enumerate_sessions_info.return_value = ["address denied"]
    result = protocol.smb.qwinsta_result(fake)
    assert result.status is ResultStatus.FAILED
    assert result.error == f"{failure} denied"
    assert len(result.data.sessions) == (0 if failure == "listing" else 1)


def test_terminal_sessions_username_file(tmp_path):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    users = tmp_path / "users.txt"
    users.write_text(" ALICE\n\n")
    fake = SimpleNamespace(host="offline.invalid", logger=Mock(), args=SimpleNamespace(qwinsta=str(users)), get_session_list=Mock(return_value={1: {"Username": "Alice"}, 2: {"Username": "Bob"}}), enumerate_sessions_info=Mock(return_value=[]))
    assert [row["id"] for row in protocol.smb.qwinsta_result(fake).data.sessions] == [1]


def test_terminal_enumeration_closes_handle_on_failure(monkeypatch):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    service = Mock()
    service.hRpcOpenEnum.return_value = "handle"
    service.hRpcGetEnumResult.side_effect = RuntimeError("enumeration denied")
    context = Mock()
    context.__enter__ = Mock(return_value=service)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(protocol.TSTS, "TermSrvEnumeration", Mock(return_value=context))
    fake = SimpleNamespace(conn=Mock(), host="offline.invalid", kerberos=False)
    with pytest.raises(RuntimeError, match="enumeration denied"):
        protocol.smb.get_session_list(fake)
    service.hRpcCloseEnum.assert_called_once_with("handle")


def test_terminal_remote_address_failure_is_reported(monkeypatch):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    details = Mock()
    details.hRpcGetSessionInformationEx.return_value = {"LSMSessionInfoExPtr": {"LSM_SessionInfo_Level1": {
        "SessionFlags": 0, "DomainName": "EXAMPLE", "UserName": "Alice",
        **dict.fromkeys(["ConnectTime", "DisconnectTime", "LogonTime", "LastInputTime"], datetime(2026, 1, 1)),
    }}}
    remote = Mock()
    remote.hRpcGetRemoteAddress.side_effect = RuntimeError("address denied")
    for name, service in [("TermSrvSession", details), ("RCMPublic", remote)]:
        context = Mock()
        context.__enter__ = Mock(return_value=service)
        context.__exit__ = Mock(return_value=False)
        monkeypatch.setattr(protocol.TSTS, name, Mock(return_value=context))
    monkeypatch.setattr(protocol.TSTS, "enum2value", Mock(return_value="WTS_SESSIONSTATE_LOCK"))
    fake = SimpleNamespace(conn=Mock(), host="offline.invalid", kerberos=False, logger=Mock())
    sessions = {1: {"Domain": "", "Username": "", "RemoteIp": ""}}
    assert protocol.smb.enumerate_sessions_info(fake, sessions) == ["Session 1 remote address: address denied"]
    assert sessions[1]["Username"] == "Alice"
