"""Offline CBT probe outcomes; no authentication to a live SQL server."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import nxc.modules.mssql_cbt as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def connection(**options):
    attrs = {"host": "offline.invalid", "port": 1433, "conn": SimpleNamespace(remoteName="offline.invalid"), "encryption": True, "args": SimpleNamespace(local_auth=False, mssql_timeout=5), "kerberos": False, "username": "alice", "password": "example", "targetDomain": "EXAMPLE", "lmhash": "", "nthash": "", "aesKey": None, "kdcHost": None, "use_kcache": False}
    attrs.update(options)
    return SimpleNamespace(**attrs)


@pytest.mark.parametrize("kerberos", [False, True])
@pytest.mark.parametrize("outcome", ["accepted", "rejected", "connect_error", "login_error", "cleanup_error"])
def test_cbt_outcomes_and_cleanup(monkeypatch, kerberos, outcome):
    probe = Mock()
    probe.login.return_value = probe.kerberosLogin.return_value = outcome != "rejected"
    if outcome == "connect_error":
        probe.connect.side_effect = RuntimeError("connect failed")
    elif outcome == "login_error":
        probe.login.side_effect = probe.kerberosLogin.side_effect = RuntimeError("login failed")
    elif outcome == "cleanup_error":
        probe.disconnect.side_effect = RuntimeError("cleanup failed")
    monkeypatch.setattr(code.tds, "MSSQL", Mock(return_value=probe))
    module = code.NXCModule()
    result = module.on_login(SimpleNamespace(log=Mock()), connection(kerberos=kerberos))
    validate_module_result(module, result, "mssql", "offline.invalid")
    assert result.status is (ResultStatus.SUCCESS if outcome == "accepted" else ResultStatus.FAILED)
    assert result.data.attempted is (outcome != "connect_error")
    assert result.data.cbt_required is (False if outcome in ("accepted", "cleanup_error") else None)
    assert result.data.authenticated_without_cbt == (True if outcome in ("accepted", "cleanup_error") else False if outcome == "rejected" else None)
    probe.disconnect.assert_called_once_with()
    if outcome != "connect_error":
        login = probe.kerberosLogin if kerberos else probe.login
        assert login.call_args.kwargs == {"cbt_fake_value": b""}


@pytest.mark.parametrize(("encryption", "local"), [(False, False), (None, False), (True, True)])
def test_cbt_unsupported_check_is_skipped(monkeypatch, encryption, local):
    factory = Mock()
    monkeypatch.setattr(code.tds, "MSSQL", factory)
    result = code.NXCModule().on_login(SimpleNamespace(log=Mock()), connection(encryption=encryption, args=SimpleNamespace(local_auth=local)))
    assert result.status is ResultStatus.SKIPPED
    assert result.data.cbt_required is None
    assert result.data.reason
    factory.assert_not_called()
