"""Offline group membership resolution and result contracts."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry
from impacket.ldap.ldaptypes import LDAP_SID

from nxc.modules import groupmembership
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def membership_entry(**attributes):
    entry = SearchResultEntry()
    entry["objectName"] = "CN=User,DC=example,DC=test"
    for index, (name, values) in enumerate(attributes.items()):
        entry["attributes"][index]["type"] = name
        for offset, value in enumerate(values if isinstance(values, list) else [values]):
            entry["attributes"][index]["vals"][offset] = value
    return entry


def user_sid():
    sid = LDAP_SID()
    sid.fromCanonical("S-1-5-21-1-2-3-1000")
    return sid.getData()


@pytest.mark.parametrize("rid", [513, 515, 1234])
@pytest.mark.parametrize("error_at", [None, "user", "primary"])
def test_primary_membership_uses_real_sid_and_preserves_errors(rid, error_at):
    context = SimpleNamespace(log=Mock())
    module = groupmembership.NXCModule()
    module.options(context, {"USER": "alex(test)"})
    connection = SimpleNamespace(host="dc.example.test")
    calls = []
    primary_dn = "CN=Actual Primary,OU=Groups,DC=example,DC=test"
    direct_dn = "CN=Direct,OU=Groups,DC=example,DC=test"

    def search(search_filter, attributes):
        calls.append(search_filter)
        if len(calls) == 1:
            assert "alex\\28test\\29" in search_filter
            connection.last_search_error = "partial user lookup" if error_at == "user" else None
            return [membership_entry(memberOf=[direct_dn, direct_dn], primaryGroupID=str(rid), objectSid=user_sid())]
        assert f"(objectSid=S-1-5-21-1-2-3-{rid})" in search_filter
        connection.last_search_error = "partial primary lookup" if error_at == "primary" else None
        return [membership_entry(distinguishedName=primary_dn)]

    connection.search = search
    result = module.on_login(context, connection)
    validate_module_result(module, result, "ldap", connection.host)
    assert result.status is (ResultStatus.FAILED if error_at else ResultStatus.SUCCESS)
    assert result.data.user_found
    assert result.data.primary_group_id == rid
    assert result.data.primary_group == primary_dn
    assert result.data.groups == [direct_dn, primary_dn]
    assert len(calls) == 2
    if error_at:
        assert result.error == f"partial {error_at} lookup"


@pytest.mark.parametrize(("rows", "found"), [([], False), ([membership_entry()], True)])
def test_missing_user_and_empty_membership_are_distinct(rows, found):
    module = groupmembership.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"USER": "alex"})
    connection = SimpleNamespace(host="dc.example.test", last_search_error=None, search=Mock(return_value=rows))
    result = module.on_login(context, connection)
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.user_found is found
    assert result.data.groups == []
    assert result.data.primary_group is None


def test_unresolved_primary_group_preserves_direct_membership():
    module = groupmembership.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"USER": "alex"})
    connection = SimpleNamespace(host="dc.example.test", last_search_error=None, search=Mock(side_effect=[
        [membership_entry(memberOf="CN=Team,DC=example,DC=test", primaryGroupID="513", objectSid=user_sid())], [],
    ]))
    result = module.on_login(context, connection)
    assert result.data.groups == ["CN=Team,DC=example,DC=test"]
    assert result.data.primary_group_id == 513
    assert result.data.primary_group is None


@pytest.mark.parametrize("options", [{}, {"USER": ""}])
def test_user_option_is_required(options):
    with pytest.raises(SystemExit) as exc:
        groupmembership.NXCModule().options(SimpleNamespace(log=Mock()), options)
    assert exc.value.code == 1
