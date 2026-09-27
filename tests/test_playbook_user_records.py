"""Offline records for active users and user information."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def user_entry(**attrs):
    entry = SearchResultEntry()
    entry["objectName"] = "CN=User,DC=example,DC=test"
    for index, (key, value) in enumerate(attrs.items()):
        entry["attributes"][index]["type"] = key
        entry["attributes"][index]["vals"][0] = value
    return entry


@pytest.mark.parametrize("error", [None, "partial search"])
def test_active_user_records_distinguish_disabled_and_unknown(error):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    rows = [user_entry(sAMAccountName="active", userAccountControl="512", pwdLastSet="0"), user_entry(sAMAccountName="disabled", userAccountControl="514"), user_entry(sAMAccountName="unknown")]
    fake = SimpleNamespace(args=SimpleNamespace(active_users=None), logger=Mock(), playbook_mode=True, host="offline.invalid", domain="EXAMPLE", search=Mock(return_value=rows), last_search_error=error)
    result = protocol.ldap.active_users(fake)
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.SUCCESS)
    assert result.data.users == [{"sAMAccountName": "active", "userAccountControl": "512", "pwdLastSet": "0"}]
    assert result.data.disabled_count == 1
    assert result.data.unknown_status_count == 1
    assert result.error == error


@pytest.mark.parametrize("action", ["users", "active_users"])
def test_named_user_filter_is_literal(action):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    fake = SimpleNamespace(args=SimpleNamespace(users=["alex*(test)"], users_export=None, active_users=["alex*(test)"]), logger=Mock(), playbook_mode=True, host="offline.invalid", domain="EXAMPLE", search=Mock(return_value=[]), last_search_error=None)
    result = getattr(protocol.ldap, action)(fake)
    assert result.status is ResultStatus.NEGATIVE
    assert fake.search.call_args.args[0] == r"(|(sAMAccountName=alex\2a\28test\29))"


@pytest.mark.parametrize(("filter_value", "error", "expected"), [("", None, 2), ("match", None, 1), ("missing", None, 0), ("match", "partial search", 1)])
def test_info_module_retains_filtered_records(filter_value, error, expected):
    module = import_module("nxc.modules.get-info-users").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"FILTER": filter_value})
    fake = SimpleNamespace(host="offline.invalid", last_search_error=error, search=Mock(return_value=[user_entry(sAMAccountName="alice", info="match value"), user_entry(sAMAccountName="bob", info="other value")]))
    result = module.on_login(context, fake)
    validate_module_result(module, result, "ldap", fake.host)
    assert len(result.data.users) == expected
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.SUCCESS if expected else ResultStatus.NEGATIVE)
    if expected:
        assert result.data.users[0] == {"username": "alice", "info": "match value"}
