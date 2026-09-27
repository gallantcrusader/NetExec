"""Offline BASE-query tokenGroups evidence and scope restoration."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap import ldaptypes
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def sid(value):
    result = ldaptypes.LDAP_SID()
    result.fromCanonical(value)
    return result.getData()


def record(attributes):
    entry = SearchResultEntry()
    entry["objectName"] = "CN=user,DC=example,DC=test"
    for index, (name, values) in enumerate(attributes.items()):
        entry["attributes"][index]["type"] = name
        for offset, value in enumerate(values if isinstance(values, list) else [values]):
            entry["attributes"][index]["vals"][offset] = value
    return entry


@pytest.mark.parametrize("failure", [None, "missing_groups", "malformed_sid", "partial"])
def test_groups_preserved_and_scope_restored(failure):
    principal = "S-1-5-21-1-2-3-1100"
    group = "S-1-5-21-1-2-3-513"
    history = "S-1-5-21-9-8-7-1100"
    attributes = {"objectSid": sid(principal), "tokenGroups": sid(group), "sIDHistory": sid(history)}
    if failure == "missing_groups":
        del attributes["tokenGroups"]
    elif failure == "malformed_sid":
        attributes["tokenGroups"] = b"bad"
    conn = SimpleNamespace(host="offline.invalid", scope=None, last_search_error=None)

    def search(query, fields, **kwargs):
        if "baseDN" not in kwargs:
            return [record({"objectSid": sid(principal), "distinguishedName": "CN=user,DC=example,DC=test"})]
        assert int(conn.scope) == 0
        assert kwargs["baseDN"] == "CN=user,DC=example,DC=test"
        conn.last_search_error = "partial read" if failure == "partial" else None
        return [record(attributes)]
    conn.search = Mock(side_effect=search)
    module = import_module("nxc.modules.token-groups").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"PRINCIPAL": "user*)(x=*"})
    result = module.on_login(context, conn)
    validate_module_result(module, result, "ldap", conn.host)
    assert result.status is (ResultStatus.SUCCESS if failure is None else ResultStatus.FAILED)
    assert conn.scope is None
    assert "user\\2a\\29\\28x=\\2a" in conn.search.call_args_list[0].args[0]
    if failure in (None, "partial"):
        assert result.data.directory_sids == [principal, group, history]
        assert result.data.attributes["tokenGroups"] == sid(group)
        assert result.data.sid_history == [history]
    elif failure == "malformed_sid":
        assert result.data.attributes["tokenGroups"] == b"bad"


def test_missing_principal_is_negative():
    module = import_module("nxc.modules.token-groups").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"PRINCIPAL": "missing"})
    conn = SimpleNamespace(host="offline.invalid", search=Mock(return_value=[]), last_search_error=None)
    assert module.on_login(context, conn).status is ResultStatus.NEGATIVE
    conn.search.assert_called_once()
