"""Offline identity observations from registry and LDAP."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.helpers.registry import RegistryValue
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize(("value", "status", "hostname"), [(RegistryValue(True, "hypervisor.example.test\x00", 1), ResultStatus.SUCCESS, "hypervisor.example.test"), (RegistryValue(), ResultStatus.NEGATIVE, None), (RegistryValue(error="access denied"), ResultStatus.FAILED, None), (RegistryValue(True, "hypervisor\x00", 1, "cleanup failed"), ResultStatus.FAILED, "hypervisor")])
def test_hypervisor_registry_observation(monkeypatch, value, status, hostname):
    code = import_module("nxc.modules.hyperv-host")
    monkeypatch.setattr(code, "read_registry_value", Mock(return_value=value))
    module = code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(host="offline.invalid"))
    validate_module_result(module, result, "smb", "offline.invalid")
    assert result.status is status
    assert result.data.hostname == hostname
    assert result.data.registry == value
    assert result.error == value.error


@pytest.mark.parametrize("error", [None, "partial search"])
def test_whoami_preserves_attributes_and_literal_username(error):
    module = import_module("nxc.modules.whoami").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"USER": "alice*(test)"})
    entry = SearchResultEntry()
    entry["objectName"] = "CN=Alice,DC=example,DC=test"
    for index, (name, values) in enumerate([("sAMAccountName", ["alice*(test)"]), ("memberOf", ["CN=A", "CN=B"]), ("userAccountControl", ["514"])]):
        entry["attributes"][index]["type"] = name
        for offset, value in enumerate(values):
            entry["attributes"][index]["vals"][offset] = value
    conn = SimpleNamespace(host="offline.invalid", username="authenticated", ldap_connection=SimpleNamespace(_baseDN="DC=example,DC=test"), search=Mock(return_value=[entry]), last_search_error=error)
    result = module.on_login(context, conn)
    validate_module_result(module, result, "ldap", conn.host)
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.SUCCESS)
    assert result.data.users[0]["memberOf"] == ["CN=A", "CN=B"]
    assert result.data.users[0]["userAccountControl"] == "514"
    assert result.data.username == "alice*(test)"
    assert conn.search.call_args.kwargs["searchFilter"] == r"(sAMAccountName=alice\2a\28test\29)"


def test_whoami_defaults_to_authenticated_username_and_empty_is_negative():
    module = import_module("nxc.modules.whoami").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {})
    conn = SimpleNamespace(host="offline.invalid", username="alice", ldap_connection=SimpleNamespace(_baseDN="DC=example,DC=test"), search=Mock(return_value=[]), last_search_error=None)
    result = module.on_login(context, conn)
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.username == "alice"
