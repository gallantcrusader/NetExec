"""Offline module results for domain quota and site topology."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.modules import maq, subnets
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def ldap_entry(**attributes):
    entry = SearchResultEntry()
    entry["objectName"] = "DC=example,DC=test"
    for index, (name, value) in enumerate(attributes.items()):
        entry["attributes"][index]["type"] = name
        entry["attributes"][index]["vals"][0] = value
    return entry


@pytest.mark.parametrize(("quota", "error", "status"), [
    ("0", None, ResultStatus.SUCCESS),
    ("10", None, ResultStatus.SUCCESS),
    (None, None, ResultStatus.NEGATIVE),
    (None, "access denied", ResultStatus.FAILED),
    ("10", "incomplete search", ResultStatus.FAILED),
])
def test_quota_result(quota, error, status):
    connection = SimpleNamespace(host="dc.example.test", last_search_error=error)
    connection.search = Mock(return_value=[ldap_entry(**{"ms-DS-MachineAccountQuota": quota})] if quota is not None else [])
    module = maq.NXCModule()
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    validate_module_result(module, result, "ldap", connection.host)
    assert result.status is status
    assert result.error == error
    assert result.data.quota == (int(quota) if quota is not None else None)


@pytest.mark.parametrize("showservers", [True, False])
@pytest.mark.parametrize("search_error", [None, "partial sites", "subnet access denied", "server access denied"])
def test_topology_preserves_structure_and_search_errors(showservers, search_error):
    site_dn = "CN=Site (HQ),CN=Sites,CN=Configuration,DC=example,DC=test"
    calls = []
    connection = SimpleNamespace(host="dc.example.test", args=SimpleNamespace(base_dn=None), ldap_connection=SimpleNamespace(_baseDN="DC=example,DC=test"))

    def search(search_filter, attributes, baseDN):
        calls.append((search_filter, baseDN))
        connection.last_search_error = None
        if search_filter == "(objectClass=site)":
            connection.last_search_error = search_error if search_error == "partial sites" else None
            return [ldap_entry(distinguishedName=site_dn, name="Site (HQ)", description="Main site")]
        if search_filter == "(objectClass=server)":
            connection.last_search_error = search_error if search_error == "server access denied" else None
            return [ldap_entry(cn="DC01")]
        assert "Site \\28HQ\\29" in search_filter
        connection.last_search_error = search_error if search_error == "subnet access denied" else None
        return [ldap_entry(name="192.0.2.0/24", distinguishedName="CN=192.0.2.0/24"), ldap_entry(name="2001:db8::/32", distinguishedName="CN=2001:db8::/32")]

    connection.search = search
    module = subnets.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"SHOWSERVERS": str(showservers)})
    result = module.on_login(context, connection)
    validate_module_result(module, result, "ldap", connection.host)
    expected_error = search_error if showservers or search_error != "server access denied" else None
    assert result.error == expected_error
    assert result.status is (ResultStatus.FAILED if expected_error else ResultStatus.SUCCESS)
    site = result.data.sites[0]
    assert site["name"] == "Site (HQ)"
    assert site["description"] == "Main site"
    assert len(site["subnets"]) == 2
    assert site["servers"] == (["DC01"] if showservers else [])
    assert result.data.servers_queried is showservers
    assert len(calls) == (3 if showservers else 2)
    assert calls[0][1] == "CN=Configuration,DC=example,DC=test"


@pytest.mark.parametrize("error", [None, "access denied"])
def test_topology_empty_result(error):
    module = subnets.NXCModule()
    module.options(SimpleNamespace(log=Mock()), {})
    connection = SimpleNamespace(host="dc.example.test", args=SimpleNamespace(base_dn="DC=other,DC=test"), search=Mock(return_value=[]), last_search_error=error)
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.NEGATIVE)
    assert result.data.sites == []
    assert connection.search.call_args.kwargs["baseDN"] == "CN=Configuration,DC=other,DC=test"


def test_topology_site_without_subnets_still_has_servers():
    module = subnets.NXCModule()
    module.options(SimpleNamespace(log=Mock()), {})
    connection = SimpleNamespace(host="dc.example.test", args=SimpleNamespace(base_dn="DC=example,DC=test"), last_search_error=None)
    connection.search = Mock(side_effect=[[ldap_entry(name="HQ", distinguishedName="CN=HQ")], [], [ldap_entry(cn="DC01")]])
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    assert result.data.sites[0]["subnets"] == []
    assert result.data.sites[0]["servers"] == ["DC01"]
