"""Offline WDigest actions distinguish writes, read-back, and access errors."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules import wdigest as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize(("action", "scenario", "status", "completed", "verified"), [
    ("check", "one", ResultStatus.SUCCESS, False, False),
    ("check", "unexpected", ResultStatus.FAILED, False, False),
    ("check", "wrong_type", ResultStatus.FAILED, False, False),
    ("check", "zero", ResultStatus.NEGATIVE, False, False),
    ("check", "absent", ResultStatus.NEGATIVE, False, False),
    ("check", "denied", ResultStatus.FAILED, False, False),
    ("enable", "one", ResultStatus.SUCCESS, True, True),
    ("enable", "zero", ResultStatus.FAILED, True, False),
    ("enable", "denied", ResultStatus.FAILED, True, False),
    ("enable", "write_denied", ResultStatus.FAILED, False, False),
    ("disable", "absent", ResultStatus.SUCCESS, True, True),
    ("disable", "already_absent", ResultStatus.SUCCESS, False, True),
    ("disable", "one", ResultStatus.FAILED, True, False),
    ("disable", "denied", ResultStatus.FAILED, True, False),
    ("disable", "write_denied", ResultStatus.FAILED, False, False),
    ("disable", "missing_key", ResultStatus.SUCCESS, False, True),
    ("check", "missing_key", ResultStatus.NEGATIVE, False, False),
    ("enable", "missing_key", ResultStatus.FAILED, False, False),
    ("enable", "cleanup", ResultStatus.FAILED, True, True),
])
def test_wdigest_outcomes(monkeypatch, action, scenario, status, completed, verified):
    remote = Mock()
    monkeypatch.setattr(code, "RemoteOperations", Mock(return_value=remote))
    monkeypatch.setattr(code.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    open_key = Mock(return_value={"phkResult": "key"})
    if scenario == "missing_key":
        open_key.side_effect = code.rrp.DCERPCSessionError(error_code=2)
    monkeypatch.setattr(code.rrp, "hBaseRegOpenKey", open_key)
    query = Mock(return_value=(code.rrp.REG_DWORD, 0 if scenario == "zero" else 1))
    if scenario == "unexpected":
        query.return_value = (code.rrp.REG_DWORD, 2)
    elif scenario == "wrong_type":
        query.return_value = (code.rrp.REG_SZ, "1")
    if scenario in ("absent", "already_absent"):
        query.side_effect = code.rrp.DCERPCSessionError(error_code=2)
    elif scenario == "denied":
        query.side_effect = code.rrp.DCERPCSessionError(error_code=5)
    monkeypatch.setattr(code.rrp, "hBaseRegQueryValue", query)
    write, delete = Mock(), Mock()
    if scenario == "write_denied":
        write.side_effect = delete.side_effect = code.rrp.DCERPCSessionError(error_code=5)
    elif scenario == "already_absent":
        delete.side_effect = code.rrp.DCERPCSessionError(error_code=2)
    monkeypatch.setattr(code.rrp, "hBaseRegSetValue", write)
    monkeypatch.setattr(code.rrp, "hBaseRegDeleteValue", delete)
    close = Mock(side_effect=[RuntimeError("close failed"), None] if scenario == "cleanup" else None)
    monkeypatch.setattr(code.rrp, "hBaseRegCloseKey", close)
    module = code.NXCModule()
    module.options(SimpleNamespace(log=Mock()), {"ACTION": action})
    conn = SimpleNamespace(host="offline.invalid", conn=Mock())
    result = module.on_admin_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "smb", conn.host)
    assert result.status is status
    assert result.data.completed is completed
    assert result.data.verified is verified
    if scenario == "denied":
        assert result.data.observed.error
    if action == "check":
        write.assert_not_called()
        delete.assert_not_called()
    assert [call.args[1] for call in close.call_args_list] == (["root"] if scenario == "missing_key" else ["key", "root"])
    remote.finish.assert_called_once_with()
    conn.conn.close.assert_not_called()
