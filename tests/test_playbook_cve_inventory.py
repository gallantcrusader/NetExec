"""Offline patch comparisons are observations, not verified vulnerabilities."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules import enum_cve as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.fixture
def registry(monkeypatch):
    rpc = Mock()
    monkeypatch.setattr(code, "NXCRPCConnection", Mock(return_value=SimpleNamespace(connect=Mock(return_value=rpc))))
    monkeypatch.setattr(code.rrp, "hOpenLocalMachine", Mock(return_value={"phKey": "root"}))
    monkeypatch.setattr(code.rrp, "hBaseRegOpenKey", Mock(return_value={"phkResult": "key"}))
    monkeypatch.setattr(code.rrp, "hBaseRegQueryValue", Mock(return_value=(code.rrp.REG_DWORD, 0)))
    monkeypatch.setattr(code.rrp, "hBaseRegCloseKey", Mock())
    return rpc


def connection(build=20348, dc=True):
    return SimpleNamespace(host="offline.invalid", server_os_major=10, server_os_minor=0, server_os_build=build,
                           trigger_winreg=Mock(), is_host_dc=Mock(return_value=dc), conn=Mock())


@pytest.mark.parametrize(("ubr", "status"), [(0, ResultStatus.SUCCESS), (3806, ResultStatus.SUCCESS), (3807, ResultStatus.NEGATIVE)])
def test_zero_and_boundary_revisions(registry, ubr, status):
    code.rrp.hBaseRegQueryValue.return_value = (code.rrp.REG_DWORD, ubr)
    module = code.NXCModule()
    module.options(None, {"CVE": "cve-2025-33073"})
    conn = connection()
    conn.conn.isSigningRequired.return_value = True
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "smb", conn.host)
    assert result.status is status
    assert result.data.ubr == ubr
    assert result.data.checks[0]["below_patch_threshold"] is (ubr < 3807)
    assert result.data.checks[0]["minimum_patched_ubr"] == 3807
    assert [call.args[1] for call in code.rrp.hBaseRegCloseKey.call_args_list] == ["key", "root"]
    registry.disconnect.assert_called_once_with()
    conn.is_host_dc.assert_not_called()
    conn.conn.close.assert_not_called()


@pytest.mark.parametrize(("build", "dc", "status", "reason"), [
    (99999, True, ResultStatus.FAILED, "No patch threshold"),
    (26100, None, ResultStatus.FAILED, "role could not be determined"),
    (26100, False, ResultStatus.SKIPPED, "Only applicable"),
])
def test_unknown_and_inapplicable_are_distinct(registry, build, dc, status, reason):
    module = code.NXCModule()
    module.options(None, {"CVE": "CVE-2025-53779"})
    result = module.on_login(SimpleNamespace(log=Mock()), connection(build, dc))
    assert result.status is status
    assert result.data.checks[0]["below_patch_threshold"] is None
    assert reason in result.data.checks[0]["reason"]


@pytest.mark.parametrize("failure", ["query", "cleanup", "type"])
def test_errors_and_partial_observations(registry, failure):
    if failure == "query":
        code.rrp.hBaseRegQueryValue.side_effect = RuntimeError("access denied")
    elif failure == "cleanup":
        code.rrp.hBaseRegCloseKey.side_effect = [RuntimeError("close failed"), None]
    else:
        code.rrp.hBaseRegQueryValue.return_value = (code.rrp.REG_SZ, "0")
    module = code.NXCModule()
    module.options(None, {"CVE": "CVE-2025-33073"})
    result = module.on_login(SimpleNamespace(log=Mock()), connection())
    assert result.status is ResultStatus.FAILED
    assert bool(result.data.checks) == (failure == "cleanup")
    assert result.data.ubr == (0 if failure == "cleanup" else None)
    assert code.rrp.hBaseRegCloseKey.call_count == 2
    registry.disconnect.assert_called_once_with()


def test_unknown_cve_does_not_open_registry(registry):
    module = code.NXCModule()
    module.options(None, {"CVE": "unknown"})
    conn = connection()
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    assert result.status is ResultStatus.FAILED
    conn.trigger_winreg.assert_not_called()
    assert result.data.checks == []
