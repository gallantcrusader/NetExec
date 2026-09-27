"""Offline enrollment-service results and literal server selection."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.modules.adcs import NXCModule
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def enrollment(cn, templates):
    entry = SearchResultEntry()
    entry["objectName"] = f"CN={cn},CN=Enrollment Services,DC=example,DC=test"
    attrs = {"cn": [cn], "dNSHostName": ["ca.example.test"], "certificateTemplates": templates,
             "msPKI-Enrollment-Servers": ["1\r\n2\r\nhttps://ca.example.test/first\r\n", "3\nhttp://ca.example.test/second"]}
    for index, (key, values) in enumerate(attrs.items()):
        entry["attributes"][index]["type"] = key
        for offset, value in enumerate(values):
            entry["attributes"][index]["vals"][offset] = value
    return entry


@pytest.mark.parametrize("error", [None, "partial directory search"])
def test_enrollment_records_and_partial_errors(error):
    connection = SimpleNamespace(host="offline.invalid", baseDN="DC=example,DC=test", last_search_error=error,
                                 search=Mock(return_value=[enrollment("CA One", ["User", "Machine"]), enrollment("CA Two", ["User"])]))
    module = NXCModule()
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    validate_module_result(module, result, "ldap", connection.host)
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.SUCCESS)
    assert result.error == error
    assert result.data.templates == ["User", "Machine"]
    assert result.data.services[0]["templates"] == ["User", "Machine"]
    assert result.data.services[1]["templates"] == ["User"]
    assert result.data.services[0]["urls"] == ["https://ca.example.test/first", "http://ca.example.test/second"]
    assert result.data.services[0]["attributes"]["msPKI-Enrollment-Servers"][0].endswith("\r\n")
    assert connection.search.call_args.kwargs["baseDN"] == "CN=Configuration,DC=example,DC=test"


def test_server_name_escapes_dn_and_filter_with_custom_base():
    module = NXCModule()
    module.options(None, {"SERVER": "CA, (*One)", "BASE_DN": "DC=other,DC=test"})
    connection = SimpleNamespace(host="offline.invalid", baseDN="DC=example,DC=test", last_search_error=None, search=Mock(return_value=[]))
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.services == []
    assert result.data.server == "CA, (*One)"
    assert connection.search.call_args.args[0] == "(&(objectClass=pKIEnrollmentService)(distinguishedName=CN=CA\\5c, \\28\\2aOne\\29,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=other,DC=test))"
    assert connection.search.call_args.kwargs["baseDN"] == "CN=Configuration,DC=other,DC=test"


def test_missing_configuration_is_error_not_negative():
    module = NXCModule()
    connection = SimpleNamespace(host="offline.invalid", baseDN="DC=example,DC=test", last_search_error="noSuchObject", search=Mock(return_value=[]))
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    assert result.status is ResultStatus.FAILED
    assert result.error == "noSuchObject"
