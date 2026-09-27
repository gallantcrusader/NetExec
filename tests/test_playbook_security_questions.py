"""Offline SAMR pagination, reset data, and resource cleanup."""

from importlib import import_module
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def page(items, cursor=0, status=0):
    return {"Buffer": {"Buffer": items}, "EnumerationContext": cursor, "ErrorCode": status}


@pytest.mark.parametrize("scenario", ["normal", "empty", "unsupported", "denied", "invalid", "cleanup", "connect"])
def test_security_question_results(monkeypatch, scenario):
    code = import_module("nxc.modules.security-questions")
    rpc = Mock()
    connect = Mock(return_value=rpc)
    if scenario == "connect":
        connect.side_effect = RuntimeError("connect failed")
    monkeypatch.setattr(code, "NXCRPCConnection", Mock(return_value=SimpleNamespace(connect=connect)))
    monkeypatch.setattr(code.samr, "hSamrConnect", Mock(return_value={"ServerHandle": "server"}))
    domains = Mock(side_effect=[page([{"Name": "Builtin"}], 1, code.STATUS_MORE_ENTRIES), page([{"Name": "Machine"}])])
    monkeypatch.setattr(code.samr, "hSamrEnumerateDomainsInSamServer", domains)
    monkeypatch.setattr(code.samr, "hSamrLookupDomainInSamServer", Mock(side_effect=lambda rpc, server, name: {"DomainId": SimpleNamespace(formatCanonical=lambda: "S-1-5-32" if name == "Builtin" else "S-1-5-21-1")}))
    open_domain = Mock(return_value={"DomainHandle": "domain"})
    monkeypatch.setattr(code.samr, "hSamrOpenDomain", open_domain)
    users = Mock(side_effect=[page([{"Name": "alice", "RelativeId": 1001}], 1, code.STATUS_MORE_ENTRIES), page([{"Name": "bob", "RelativeId": 1002}])])
    monkeypatch.setattr(code.samr, "hSamrEnumerateUsersInDomain", users)
    monkeypatch.setattr(code.samr, "hSamrOpenUser", Mock(side_effect=lambda rpc, domain, access, rid: {"UserHandle": rid}))
    raw = b"" if scenario == "empty" else b"bad json" if scenario == "invalid" else json.dumps({"questions": [{"question": "Question", "answer": "Answer"}], "version": 1})
    query = Mock(return_value={"Buffer": {"Reset": {"ResetData": raw}}})
    if scenario in ("unsupported", "denied"):
        query.side_effect = code.samr.DCERPCSessionError(error_code=code.STATUS_INVALID_INFO_CLASS if scenario == "unsupported" else 0xC0000022)
    monkeypatch.setattr(code.samr, "hSamrQueryInformationUser2", query)
    close = Mock(side_effect=[RuntimeError("close failed"), None, None] if scenario == "cleanup" else None)
    monkeypatch.setattr(code.samr, "hSamrCloseHandle", close)
    module = code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(host="offline.invalid"))
    validate_module_result(module, result, "smb", "offline.invalid")
    expected = {"normal": ResultStatus.SUCCESS, "empty": ResultStatus.NEGATIVE, "unsupported": ResultStatus.SKIPPED}
    assert result.status is expected.get(scenario, ResultStatus.FAILED)
    if scenario == "connect":
        close.assert_not_called()
        rpc.disconnect.assert_not_called()
        assert result.data.users == []
    else:
        open_domain.assert_called_once()
        closed = [call.args[1] for call in close.call_args_list]
        assert closed == ([1001, 1002, "domain", "server"] if scenario in ("normal", "empty", "unsupported") else [1001, "domain", "server"])
        rpc.disconnect.assert_called_once_with()
        if scenario == "normal":
            assert result.data.users[0]["reset_data"]["version"] == 1
            assert result.data.users[1]["rid"] == 1002
            assert [call.kwargs["enumerationContext"] for call in users.call_args_list] == [0, 1]
        elif scenario == "invalid":
            assert result.data.users[0]["raw"] == raw
            assert result.data.users[0]["error"]


def test_pagination_rejects_stalled_cursor():
    code = import_module("nxc.modules.security-questions")
    module = code.NXCModule()
    with pytest.raises(RuntimeError, match="did not advance"):
        list(module.enumerate_entries(None, None, Mock(return_value=page([], 0, code.STATUS_MORE_ENTRIES))))
