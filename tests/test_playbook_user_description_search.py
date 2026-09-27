"""Offline user-description keyword search, filtering, and exports."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.playbooks.results import ResultStatus


def entry(descriptions):
    result = SearchResultEntry()
    result["objectName"] = "CN=Alice,DC=example,DC=test"
    for index, (name, values) in enumerate([("sAMAccountName", ["alice"]), ("description", descriptions)]):
        result["attributes"][index]["type"] = name
        for offset, value in enumerate(values):
            result["attributes"][index]["vals"][offset] = value
    return result


@pytest.mark.parametrize("failure", [None, "search", "file"])
def test_descriptions_preserve_multiple_values_and_partial_failures(monkeypatch, tmp_path, failure):
    code = import_module("nxc.modules.user-desc")
    root = tmp_path / "output"
    if failure == "file":
        root.write_text("file")
    monkeypatch.setattr(code, "NXC_PATH", root)
    module = code.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"KEYWORDS": "PASS,token"})
    row = entry(["Contains password", "Other info"])
    conn = SimpleNamespace(host="offline.invalid", search=Mock(return_value=[row, row]), last_search_error="partial search" if failure == "search" else None)
    result = module.on_login(context, conn)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.users == [{"username": "alice", "descriptions": ["Contains password", "Other info"], "matched_keywords": ["PASS"]}]
    if failure == "file":
        assert result.artifacts == []
    else:
        content = result.artifacts[0].path.read_text()
        assert "Other info" in content
        assert content.count("Contains password") == 1


def test_filter_preserves_wildcards_but_escapes_parentheses():
    module = import_module("nxc.modules.user-desc").NXCModule()
    module.options(SimpleNamespace(log=Mock()), {"USER_FILTER": "alice*(test)"})
    assert module.search_filter == r"(&(objectclass=user)(sAMAccountName=alice*\28test\29))"
    module.options(SimpleNamespace(log=Mock()), {"LDAP_FILTER": "(custom=*)"})
    assert module.search_filter == "(custom=*)"
