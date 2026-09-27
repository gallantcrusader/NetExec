"""Offline checks for description records and composable module filters."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.capture import RecordingLogger
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def description_entry(username, description=None):
    entry = SearchResultEntry()
    entry["objectName"] = f"CN={username},DC=example,DC=test"
    attributes = {"sAMAccountName": username}
    if description is not None:
        attributes["description"] = description
    for index, (key, value) in enumerate(attributes.items()):
        entry["attributes"][index]["type"] = key
        entry["attributes"][index]["vals"][0] = value
    return entry


@pytest.mark.parametrize(("options", "expected"), [
    ({}, ["alice", "bob", "carol"]),
    ({"FILTER": "hello"}, ["alice", "bob"]),
    ({"FILTER": "missing"}, []),
    ({"PASSWORDPOLICY": "true"}, ["bob", "carol"]),
    ({"PASSWORDPOLICY": "false"}, ["alice", "bob", "carol"]),
    ({"FILTER": "hello", "PASSWORDPOLICY": "true"}, ["bob"]),
    ({"PASSWORDPOLICY": "true", "MINLENGTH": "20"}, []),
])
def test_description_filters_return_records(options, expected):
    module = import_module("nxc.modules.get-desc-users").NXCModule()
    context = SimpleNamespace(log=RecordingLogger(Mock()))
    module.options(context, options)
    rows = [description_entry("alice", "hello"), description_entry("bob", "hello Abc123!"), description_entry("carol", "Xyz987!"), description_entry("empty")]

    def search(search_filter, attributes):
        assert search_filter == "(objectclass=user)"
        assert attributes == ["sAMAccountName", "description"]
        return rows

    connection = SimpleNamespace(host="dc.example.test", search=search, last_search_error=None)
    result = module.on_login(context, connection)
    validate_module_result(module, result, "ldap", connection.host)
    assert [item["username"] for item in result.data.users] == expected
    assert result.status is (ResultStatus.SUCCESS if expected else ResultStatus.NEGATIVE)
    if "bob" in expected:
        assert next(item["description"] for item in result.data.users if item["username"] == "bob") == "hello Abc123!"


def test_description_search_failure_retains_partial_results():
    module = import_module("nxc.modules.get-desc-users").NXCModule()
    context = SimpleNamespace(log=RecordingLogger(Mock()))
    module.options(context, {})
    connection = SimpleNamespace(host="dc.example.test", search=lambda *args: [description_entry("alice", "hello")], last_search_error="sizeLimitExceeded")
    result = module.on_login(context, connection)
    assert result.status is ResultStatus.FAILED
    assert result.error == "sizeLimitExceeded"
    assert result.data.users == [{"username": "alice", "description": "hello"}]


def test_ldap_search_preserves_server_partial_answers():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    rows = [description_entry("alice", "hello")]

    def search(**kwargs):
        raise protocol.ldap_impacket.LDAPSearchError(errorString="sizeLimitExceeded", answers=rows)

    connection = SimpleNamespace(args=SimpleNamespace(base_dn=None), baseDN="DC=example,DC=test", ldap_connection=SimpleNamespace(search=search), logger=RecordingLogger(Mock()), no_ntlm=False, scope=None)
    assert protocol.ldap.search(connection, "(objectclass=user)", ["description"]) == rows
    assert "sizeLimitExceeded" in connection.last_search_error
