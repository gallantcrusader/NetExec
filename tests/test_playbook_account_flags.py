"""Offline structured account-flag searches."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize(("action", "filter_text"), [
    ("admin_count", "(&(adminCount=1)(objectClass=user))"),
    ("trusted_for_delegation", "(userAccountControl:1.2.840.113556.1.4.803:=524288)"),
    ("password_not_required", "(userAccountControl:1.2.840.113556.1.4.803:=32)"),
])
@pytest.mark.parametrize(("with_rows", "error"), [(True, None), (False, None), (True, "partial search"), (False, "access denied")])
def test_account_search_preserves_records_and_failures(action, filter_text, with_rows, error):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    entry = SearchResultEntry()
    entry["objectName"] = "CN=User,DC=example,DC=test"
    entry["attributes"][0]["type"] = "sAMAccountName"
    entry["attributes"][0]["vals"][0] = "alice"
    if action == "password_not_required":
        entry["attributes"][1]["type"] = "userAccountControl"
        entry["attributes"][1]["vals"][0] = "546"
    fake = SimpleNamespace(host="offline.invalid", domain="EXAMPLE", baseDN="DC=example,DC=test", logger=Mock(), playbook_mode=True, last_search_error=error, search=Mock(return_value=[entry] if with_rows else []))
    result = getattr(protocol.ldap, action)(fake)
    assert result.action == action
    assert result.data.domain == "EXAMPLE"
    assert result.data.search_filter == filter_text
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.SUCCESS if with_rows else ResultStatus.NEGATIVE)
    assert result.error == error
    assert len(result.data.accounts) == int(with_rows)
    if with_rows:
        assert result.to_dict()["data"]["accounts"][0]["sAMAccountName"] == "alice"
        if action == "password_not_required":
            assert result.data.accounts[0]["userAccountControl"] == "546"
            assert "disabled" in fake.logger.highlight.call_args.args[0]
