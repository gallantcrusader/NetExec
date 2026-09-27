"""Offline fine-grained password policy records and partial failures."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry, SearchResultReference

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


def pso_entry(dn, **attrs):
    entry = SearchResultEntry()
    entry["objectName"] = dn
    for index, (key, values) in enumerate(attrs.items()):
        entry["attributes"][index]["type"] = key
        for offset, value in enumerate(values if isinstance(values, list) else [values]):
            entry["attributes"][index]["vals"][offset] = value
    return entry


@pytest.mark.parametrize("error_stage", [None, 0, 1, 2])
def test_pso_keeps_assignments_raw_policy_values_and_earlier_errors(error_stage):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    fake = SimpleNamespace(host="offline.invalid", baseDN="DC=example,DC=test", logger=Mock(), playbook_mode=True)
    referral = SearchResultReference()
    referral[0] = "ldap://other.example.test"
    policy_dn = "CN=Policy,CN=System,DC=example,DC=test"
    policy = {"name": "Policy", "distinguishedName": policy_dn, "msDS-LockoutDuration": "-54000000000", "msDS-MinimumPasswordLength": "14", "msds-maximumpasswordage": "-38880000000000"}
    responses = [
        [pso_entry(policy_dn, name="Policy")],
        [referral, pso_entry("CN=First", **{"msDS-PSOApplied": policy_dn}), pso_entry("CN=Second", **{"msds-psoapplied": [policy_dn, "CN=Other"]})],
        [pso_entry(policy_dn, **policy)],
    ]
    calls = []

    def search(**kwargs):
        stage = len(calls)
        calls.append(kwargs)
        fake.last_search_error = f"stage {stage} failed" if stage == error_stage else None
        return responses[stage]

    fake.search = search
    result = protocol.ldap.pso(fake)
    assert result.status is (ResultStatus.FAILED if error_stage is not None else ResultStatus.SUCCESS)
    assert result.error == (f"stage {error_stage} failed" if error_stage is not None else None)
    assert result.data.policies == [policy]
    assert result.data.assignments == [
        {"distinguished_name": "CN=First", "policies": [policy_dn]},
        {"distinguished_name": "CN=Second", "policies": [policy_dn, "CN=Other"]},
    ]
    messages = [call.args[0] for call in fake.logger.highlight.call_args_list]
    assert "Object: CN=First" in messages
    assert "Object: CN=Second" in messages
    assert "Lockout Duration: 90 minutes" in messages
    assert "Maximum Password Age: 45 days" in messages
    assert result.to_dict()["data"]["policies"][0]["msDS-MinimumPasswordLength"] == "14"


@pytest.mark.parametrize("error", [None, "access denied"])
def test_pso_empty_result(error):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    fake = SimpleNamespace(host="offline.invalid", baseDN="DC=example,DC=test", logger=Mock(), playbook_mode=True, last_search_error=error, search=Mock(return_value=[]))
    result = protocol.ldap.pso(fake)
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.NEGATIVE)
    assert result.data.policies == []
    assert result.data.assignments == []
