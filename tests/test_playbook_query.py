"""LDAP query records retain object identity across referrals and printing."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry, SearchResultReference

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


def query_entry(dn, values):
    entry = SearchResultEntry()
    entry["objectName"] = dn
    entry["attributes"][0]["type"] = "memberOf"
    for index, value in enumerate(values):
        entry["attributes"][0]["vals"][index] = value
    return entry


def query_connection(rows, error=None):
    return SimpleNamespace(args=SimpleNamespace(query=["(objectClass=user)", "  memberOf\t objectGUID  "]), logger=Mock(), search=Mock(return_value=rows), host="offline.invalid", playbook_mode=True, last_search_error=error)


def test_referrals_do_not_shift_object_identity_or_drop_values():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    referral = SearchResultReference()
    referral[0] = "ldap://other.example.test"
    first = query_entry("CN=First,DC=example,DC=test", ["CN=One", "CN=Two"])
    second = query_entry("CN=Second,DC=example,DC=test", ["CN=Three"])
    fake = query_connection([referral, referral, first, referral, second, referral])
    result = protocol.ldap.query(fake)
    assert result.data.distinguished_names == [str(first["objectName"]), str(second["objectName"])]
    assert result.data.entries == [{"memberOf": ["CN=One", "CN=Two"]}, {"memberOf": "CN=Three"}]
    assert [call.args[0] for call in fake.logger.success.call_args_list] == [f"Response for object: {dn}" for dn in result.data.distinguished_names]
    assert result.data.attributes == ["memberOf", "objectGUID"]
    fake.search.assert_called_once_with("(objectClass=user)", ["memberOf", "objectGUID"], 0)
    assert result.to_dict()["data"]["entries"][0]["memberOf"] == ["CN=One", "CN=Two"]


@pytest.mark.parametrize("error", [None, "access denied"])
@pytest.mark.parametrize("with_records", [True, False])
def test_query_distinguishes_absence_from_failure(error, with_records):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    rows = [query_entry("CN=First", ["CN=One"])] if with_records else []
    fake = query_connection(rows, error)
    result = protocol.ldap.query(fake)
    expected = ResultStatus.FAILED if error else ResultStatus.SUCCESS if with_records else ResultStatus.NEGATIVE
    assert result.status is expected
    assert result.error == error
    assert len(result.data.entries) == int(with_records)


def test_query_blank_attributes_request_all_attributes():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    fake = query_connection([])
    fake.args.query[1] = " \t "
    result = protocol.ldap.query(fake)
    assert result.data.attributes is None
    fake.search.assert_called_once_with("(objectClass=user)", None, 0)
