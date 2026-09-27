"""Offline legacy OS filter records and exports."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

import nxc.modules.obsolete as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def entry(**attrs):
    result = SearchResultEntry()
    result["objectName"] = "CN=Computer,DC=example,DC=test"
    for index, (name, value) in enumerate(attrs.items()):
        result["attributes"][index]["type"] = name
        result["attributes"][index]["vals"][0] = value
    return result


@pytest.mark.parametrize("failure", [None, "dns", "ldap", "file"])
def test_obsolete_records_keep_errors_and_export(monkeypatch, tmp_path, failure):
    root = tmp_path / "output"
    if failure == "file":
        root.write_text("not a directory")
    monkeypatch.setattr(code, "NXC_PATH", root)
    conn = SimpleNamespace(host="offline.invalid", domain="EXAMPLE", last_search_error="partial LDAP" if failure == "ldap" else None, search=Mock(return_value=[entry(dNSHostName="legacy.example.test", operatingSystem="Windows 7"), entry(dNSHostName="missing-os.example.test")]), resolver=Mock(return_value=None if failure == "dns" else {"host": "192.0.2.1"}))
    module = code.NXCModule()
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "ldap", conn.host)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert len(result.data.computers) == 1
    assert result.data.computers[0]["pwdLastSet_readable"] is None
    assert result.data.computers[0]["operatingSystem"] == "Windows 7"
    assert bool(result.error) is (failure is not None)
    if failure == "file":
        assert result.artifacts == []
    else:
        assert "Windows 7" in result.artifacts[0].path.read_text()
        assert "offline.invalid" in result.artifacts[0].path.name
    conn.resolver.assert_called_once_with("legacy.example.test")


def test_no_obsolete_records_creates_no_artifact():
    conn = SimpleNamespace(host="offline.invalid", last_search_error=None, search=Mock(return_value=[]))
    result = code.NXCModule().on_login(SimpleNamespace(log=Mock()), conn)
    assert result.status is ResultStatus.NEGATIVE
    assert result.artifacts == []
