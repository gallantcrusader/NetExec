"""Offline policy configuration and registry observations."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.helpers.registry import RegistryValue
from nxc.modules import onelogon as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("scenario", ["utf8", "utf16", "missing", "denied", "partial", "invalid", "empty"])
def test_policy_inventory(scenario):
    module = code.NXCModule()
    setting = f'MACHINE\\{module.registry_key}\\{module.registry_name}=7,"D:(A;;RC;;;WD)"'
    text = "[Registry Values]\n" + setting + '\n[Service General Setting]\n"WinRM",2,""\n'
    if scenario == "invalid":
        text = "invalid INI"
    elif scenario == "empty":
        text = "[Registry Values]\nother=1\n"
    raw = text.encode("utf-16" if scenario == "utf16" else "utf-8")
    smb = Mock()
    smb.listPath.return_value = [SimpleNamespace(get_longname=lambda: "policy", is_directory=lambda: True)]

    def download(share, path, callback):
        if scenario == "missing":
            raise code.SessionError(code.STATUS_OBJECT_NAME_NOT_FOUND)
        if scenario == "denied":
            raise code.SessionError(0xC0000022)
        callback(raw)
        if scenario == "partial":
            raise RuntimeError("read failed")

    smb.getFile.side_effect = download
    conn = SimpleNamespace(host="offline.invalid", targetDomain="example.test", conn=smb)
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "smb", conn.host)
    failed = scenario in ("denied", "partial", "invalid")
    assert result.status is (ResultStatus.FAILED if failed else ResultStatus.NEGATIVE if scenario in ("missing", "empty") else ResultStatus.SUCCESS)
    if scenario == "missing":
        assert result.data.policies == []
    else:
        record = result.data.policies[0]
        assert record["content"] == (b"" if scenario == "denied" else raw)
        if scenario in ("utf8", "utf16"):
            assert record["matches"][0]["fields"] == ["7", "D:(A;;RC;;;WD)"]
            assert record["matches"][0]["raw_value"] == '7,"D:(A;;RC;;;WD)"'
    smb.close.assert_not_called()


@pytest.mark.parametrize("scenario", ["present", "missing", "error"])
def test_registry_observation(monkeypatch, scenario):
    observed = RegistryValue(present=scenario != "missing", value="raw\x00" if scenario != "missing" else None, registry_type=1, error="cleanup failed" if scenario == "error" else None)
    monkeypatch.setattr(code, "read_registry_value", Mock(return_value=observed))
    module = code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(host="offline.invalid"))
    validate_module_result(module, result, "smb", "offline.invalid")
    assert result.status is (ResultStatus.FAILED if scenario == "error" else ResultStatus.NEGATIVE if scenario == "missing" else ResultStatus.SUCCESS)
    assert result.data.registry is observed
    assert result.data.source == "registry"
