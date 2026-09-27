"""Offline computer search and DNS result contracts."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def computer(**attributes):
    entry = SearchResultEntry()
    entry["objectName"] = "CN=Computer,DC=example,DC=test"
    for index, (key, value) in enumerate(attributes.items()):
        entry["attributes"][index]["type"] = key
        entry["attributes"][index]["vals"][0] = value
    return entry


@pytest.mark.parametrize(("resolution", "error"), [({"host": "192.0.2.10"}, None), ({"host": "2001:db8::10"}, None), (None, None), ({"host": "192.0.2.10"}, "partial LDAP search")])
def test_computer_search_preserves_records_and_failures(resolution, error):
    module = import_module("nxc.modules.find-computer").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"TEXT": "SQL*(test)"})
    connection = SimpleNamespace(host="offline.invalid", last_search_error=error, search=Mock(return_value=[computer(dNSHostName="sql.example.test"), computer(operatingSystem="Windows")]), resolver=Mock(return_value=resolution))
    result = module.on_login(context, connection)
    validate_module_result(module, result, "ldap", connection.host)
    assert result.status is (ResultStatus.FAILED if error or resolution is None else ResultStatus.SUCCESS)
    assert result.data.text == "SQL*(test)"
    assert len(result.data.computers) == 1
    record = result.data.computers[0]
    assert record["operating_system"] is None
    assert record["address"] == (resolution["host"] if resolution else None)
    assert bool(record["resolution_error"]) is (resolution is None)
    connection.resolver.assert_called_once_with("sql.example.test")
    assert connection.search.call_args.kwargs["searchFilter"] == r"(&(objectCategory=computer)(|(operatingSystem=*SQL\2a\28test\29*)(name=*SQL\2a\28test\29*)))"
    if error:
        assert error in result.error


def test_no_matches_is_negative_and_skips_resolution():
    module = import_module("nxc.modules.find-computer").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"TEXT": "missing"})
    connection = SimpleNamespace(host="offline.invalid", last_search_error=None, search=Mock(return_value=[]), resolver=Mock())
    result = module.on_login(context, connection)
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.computers == []
    connection.resolver.assert_not_called()
