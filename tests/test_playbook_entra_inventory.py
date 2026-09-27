"""Offline sync-server candidates preserve LDAP evidence and lookup failures."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def entry(attrs):
    record = SearchResultEntry()
    record["objectName"] = "CN=Example,DC=test"
    for index, (name, values) in enumerate(attrs.items()):
        record["attributes"][index]["type"] = name
        for offset, value in enumerate(values):
            record["attributes"][index]["vals"][offset] = value
    return record


@pytest.mark.parametrize("scenario", ["normal", "unresolved", "dns", "partial", "empty"])
def test_sync_candidates(scenario):
    module = import_module("nxc.modules.entra-id").NXCModule()
    account = entry({"sAMAccountName": ["MSOL_test"], "description": ["computer host(*) configured", "unrelated"]})
    msa = entry({"sAMAccountName": ["ADSyncMSAtest"], "msDS-HostServiceAccountBL": ["CN=one,DC=test", "CN=two,DC=test"]})
    computer = entry({"cn": ["host(*)"], "dNSHostName": ["host.example.test"]})
    conn = SimpleNamespace(host="offline.invalid", last_search_error=None, resolver=Mock(return_value={"host": "192.0.2.1"}))
    if scenario == "dns":
        conn.resolver.side_effect = RuntimeError("DNS failed")

    def search(query, attrs):
        conn.last_search_error = None
        if query == "(sAMAccountName=MSOL_*)":
            if scenario == "partial":
                conn.last_search_error = "partial search"
            return [] if scenario == "empty" else [account]
        if query == "(sAMAccountName=ADSyncMSA*)":
            return [] if scenario == "empty" else [msa]
        return [] if scenario == "unresolved" else [computer]
    conn.search = Mock(side_effect=search)
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "ldap", conn.host)
    assert result.status is (ResultStatus.FAILED if scenario in ("dns", "partial") else ResultStatus.NEGATIVE if scenario == "empty" else ResultStatus.SUCCESS)
    if scenario == "partial":
        assert result.data.msol_accounts
        assert result.data.adsync_accounts == []
        assert conn.search.call_count == 1
    elif scenario == "empty":
        assert result.data.candidates == []
    else:
        assert conn.search.call_args_list[2].args[0] == "(sAMAccountName=host\\28\\2a\\29$)"
        assert result.data.candidates[0]["account"] == "MSOL_test"
        if scenario == "dns":
            assert result.data.candidates[0]["resolution_error"] == "DNS failed"
        else:
            assert len(result.data.candidates) == 3
            assert result.data.candidates[2]["evidence"] == "CN=two,DC=test"
            if scenario == "unresolved":
                assert result.data.candidates[1]["computers"] == []
