"""Offline structured account-flag searches."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.dcerpc.v5.samr import UF_SERVER_TRUST_ACCOUNT
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


def test_find_delegation_returns_structured_rbcd_result(monkeypatch):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")

    class Sid:
        def formatCanonical(self):
            return "S-1-5-21-111-222-333-4444"

    class Ace:
        def __getitem__(self, key):
            assert key == "Ace"
            return {"Sid": Sid()}

    class Dacl:
        aces = [Ace()]

    class SecurityDescriptor:
        def __init__(self, data):
            assert data == b"descriptor"

        def __getitem__(self, key):
            assert key == "Dacl"
            return Dacl()

    entries = iter([
        [{
            "sAMAccountName": "CPTS-DC02$",
            "userAccountControl": str(UF_SERVER_TRUST_ACCOUNT),
            "objectCategory": "CN=Computer,CN=Schema,CN=Configuration,DC=example,DC=test",
            "msDS-AllowedToActOnBehalfOfOtherIdentity": b"descriptor",
        }],
        [{
            "sAMAccountName": "svc_buildlink$",
            "objectCategory": "CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=example,DC=test",
        }],
    ])
    method_globals = protocol.ldap.find_delegation.__globals__
    monkeypatch.setitem(method_globals, "parse_result_attributes", lambda _resp: next(entries))
    monkeypatch.setattr(method_globals["ldaptypes"], "SR_SECURITY_DESCRIPTOR", SecurityDescriptor)
    fake = SimpleNamespace(
        host="192.0.2.10", domain="EXAMPLE", playbook_mode=True, last_search_error=None,
        logger=Mock(), search=Mock(side_effect=["dc-result", "principal-result"]),
    )

    result = protocol.ldap.find_delegation(fake)

    assert result.action == "find_delegation"
    assert result.status is ResultStatus.SUCCESS
    assert result.data.delegations == [{
        "account_name": "svc_buildlink$",
        "account_type": "CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=example,DC=test",
        "delegation_type": "Resource-Based Constrained",
        "delegation_rights_to": "CPTS-DC02$",
    }]
    assert "msDS-AllowedToActOnBehalfOfOtherIdentity" in result.data.search_filter
    assert "objectSid=" not in result.data.search_filter
    assert result.to_dict()["data"]["delegations"][0]["account_name"] == "svc_buildlink$"


def test_find_delegation_marks_partial_sid_lookup_as_failed(monkeypatch):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")

    class Sid:
        def formatCanonical(self):
            return "S-1-5-21-111-222-333-4444"

    class Ace:
        def __getitem__(self, key):
            assert key == "Ace"
            return {"Sid": Sid()}

    class Dacl:
        aces = [Ace()]

    class SecurityDescriptor:
        def __init__(self, data):
            assert data == b"descriptor"

        def __getitem__(self, key):
            assert key == "Dacl"
            return Dacl()

    entries = iter([
        [{
            "sAMAccountName": "CPTS-DC02$",
            "userAccountControl": str(UF_SERVER_TRUST_ACCOUNT),
            "objectCategory": "CN=Computer,CN=Schema,CN=Configuration,DC=example,DC=test",
            "msDS-AllowedToActOnBehalfOfOtherIdentity": b"descriptor",
        }],
        [{
            "sAMAccountName": "svc_buildlink$",
            "objectCategory": "CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=example,DC=test",
        }],
    ])
    method_globals = protocol.ldap.find_delegation.__globals__
    monkeypatch.setitem(method_globals, "parse_result_attributes", lambda _resp: next(entries))
    monkeypatch.setattr(method_globals["ldaptypes"], "SR_SECURITY_DESCRIPTOR", SecurityDescriptor)
    fake = SimpleNamespace(
        host="192.0.2.10", domain="EXAMPLE", playbook_mode=True, last_search_error=None,
        logger=Mock(), search=None,
    )
    calls = 0

    def search(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        fake.last_search_error = "one principal lookup failed" if calls == 2 else None
        return "search-result"

    fake.search = Mock(side_effect=search)

    result = protocol.ldap.find_delegation(fake)

    assert result.status is ResultStatus.FAILED
    assert result.error == "one principal lookup failed"
    assert result.data.delegations[0]["account_name"] == "svc_buildlink$"
