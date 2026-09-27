"""Retired hooks return an explicit failure without invoking replacements."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize(("name", "protocol", "replacement"), [
    ("dfscoerce", "smb", "module:coerce_plus"),
    ("petitpotam", "smb", "module:coerce_plus"),
    ("printerbug", "smb", "module:coerce_plus"),
    ("shadowcoerce", "smb", "module:coerce_plus"),
    ("efsr_spray", "smb", "module:coerce_plus"),
    ("firefox", "smb", "action:dpapi"),
    ("ntlm_reflection", "smb", "module:enum_cve"),
    ("group-mem", "ldap", "action:groups"),
    ("pso", "ldap", "action:pso"),
    ("enum_trusts", "ldap", "action:dc_list"),
    ("ldap-checker", "ldap", "connection:ldap"),
])
def test_retired_module_contract(name, protocol, replacement):
    module = import_module(f"nxc.modules.{name}").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"GROUP": "unused"})
    # No network-capable attributes: any attempt to use a connection will fail.
    connection = SimpleNamespace(args=SimpleNamespace(protocol=protocol), host="offline.invalid")
    hook = module.on_admin_login if name == "firefox" else module.on_login
    result = hook(context, connection)
    validate_module_result(module, result, protocol, connection.host)
    assert result.status is ResultStatus.FAILED
    assert result.data.replacement == replacement
    assert "[REMOVED]" in result.error
