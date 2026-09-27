"""Offline LDAP attribute preservation and script-path artifacts."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def record(attribute, values):
    entry = SearchResultEntry()
    entry["objectName"] = "CN=User,DC=example,DC=test"
    for index, (name, items) in enumerate([("sAMAccountName", ["alice"]), (attribute, values)]):
        entry["attributes"][index]["type"] = name
        for offset, value in enumerate(items):
            entry["attributes"][index]["vals"][offset] = value
    return entry


@pytest.mark.parametrize("attribute", ["userPassword", "unixUserPassword"])
@pytest.mark.parametrize("error", [None, "partial search"])
def test_password_attributes_preserve_multivalues(attribute, error):
    module = import_module(f"nxc.modules.get-{attribute}").NXCModule()
    connection = SimpleNamespace(host="offline.invalid", last_search_error=error, search=Mock(return_value=[record(attribute, ["value1", "value2"])]))
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    validate_module_result(module, result, "ldap", connection.host)
    assert result.data.users == [{"sAMAccountName": "alice", attribute: ["value1", "value2"]}]
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.SUCCESS)
    assert result.error == error


@pytest.mark.parametrize("attribute", ["userPassword", "unixUserPassword"])
def test_no_attributes_is_negative(attribute):
    module = import_module(f"nxc.modules.get-{attribute}").NXCModule()
    connection = SimpleNamespace(host="offline.invalid", last_search_error=None, search=Mock(return_value=[]))
    assert module.on_login(SimpleNamespace(log=Mock()), connection).status is ResultStatus.NEGATIVE


@pytest.mark.parametrize("fail_write", [False, True])
def test_scriptpath_artifact_and_write_failure(tmp_path, fail_write):
    module = import_module("nxc.modules.get-scriptpath").NXCModule()
    context = SimpleNamespace(log=Mock())
    path = tmp_path / "scripts.json" if not fail_write else tmp_path / "missing" / "scripts.json"
    module.options(context, {"OUTPUTFILE": str(path), "FILTER": "logon"})
    connection = SimpleNamespace(host="offline.invalid", last_search_error=None, search=Mock(return_value=[record("scriptPath", [r"scripts\logon.cmd"]), record("scriptPath", ["other.cmd"])]))
    result = module.on_login(context, connection)
    validate_module_result(module, result, "ldap", connection.host)
    assert len(result.data.users) == 1
    assert result.status is (ResultStatus.FAILED if fail_write else ResultStatus.SUCCESS)
    if fail_write:
        assert result.error
        assert result.artifacts == []
    else:
        assert result.artifacts[0].path == path
        assert "logon.cmd" in path.read_text()
