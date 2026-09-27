"""Offline binary ACL preservation, filtering, missing data, and backup checks."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap import ldaptypes
from impacket.ldap.ldapasn1 import SearchResultEntry
from impacket.uuid import string_to_bin

from nxc.helpers.security_descriptor import descriptor_evidence
from nxc.modules import daclread
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def ace(ace_type=0, mask=0x40000, flags=0, guid=None):
    result = ldaptypes.ACE()
    result["AceType"] = ace_type
    result["AceFlags"] = flags
    result["Ace"] = ldaptypes.ACE_TYPE_MAP[ace_type]()
    result["Ace"]["Mask"] = ldaptypes.ACCESS_MASK()
    result["Ace"]["Mask"]["Mask"] = mask
    result["Ace"]["Sid"] = ldaptypes.LDAP_SID()
    result["Ace"]["Sid"].fromCanonical("S-1-5-21-1-2-3-1100")
    if ace_type in (5, 6):
        result["Ace"]["Flags"] = 1 if guid else 0
        result["Ace"]["ObjectType"] = string_to_bin(guid) if guid else b""
        result["Ace"]["InheritedObjectType"] = b""
    return result


def descriptor(aces=(), present=True, null=False):
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004 if present else 0x8000
    sd["Sacl"] = b""
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-21-1-2-3-500")
    sd["GroupSid"] = b""
    sd["Dacl"] = b""
    if not null and present:
        sd["Dacl"] = ldaptypes.ACL()
        sd["Dacl"]["AclRevision"] = 4
        sd["Dacl"]["Sbz1"] = 0
        sd["Dacl"]["Sbz2"] = 0
        sd["Dacl"].aces = list(aces)
    return sd.getData()


def entry(raw=None):
    result = SearchResultEntry()
    result["objectName"] = "CN=Target,DC=example,DC=test"
    attributes = {"distinguishedName": "CN=Target,DC=example,DC=test"}
    if raw is not None:
        attributes["nTSecurityDescriptor"] = raw
    for index, (name, value) in enumerate(attributes.items()):
        result["attributes"][index]["type"] = name
        result["attributes"][index]["vals"][0] = value
    return result


def test_ace_order_types_flags_masks_and_guids_are_preserved():
    guid = "00299570-246d-11d0-a768-00aa006e0529"
    raw = descriptor([ace(1), ace(0, flags=24), ace(5, mask=256, guid=guid), ace(2)])
    data = descriptor_evidence(raw)
    assert data["raw"] == raw
    assert data["owner_sid"] == "S-1-5-21-1-2-3-500"
    assert [row["index"] for row in data["aces"]] == [0, 1, 2, 3]
    assert data["aces"][0]["access"] == "denied"
    assert data["aces"][1]["inherited"]
    assert data["aces"][1]["inherit_only"]
    assert data["aces"][1]["mask"] == 0x40000
    assert data["aces"][2]["object_type"] == guid
    assert not data["aces"][3]["supported"]
    assert data["aces"][3]["raw"]


@pytest.mark.parametrize(("present", "null"), [(True, False), (True, True), (False, False)])
def test_empty_null_and_absent_dacl_distinguished(present, null):
    result = descriptor_evidence(descriptor(present=present, null=null))
    assert result["dacl_present"] is present
    assert result["null_dacl"] is null
    assert result["aces"] == []


def test_security_descriptor_attribute_stays_binary():
    assert parse_result_attributes([entry(b"ascii and null\x00")])[0]["nTSecurityDescriptor"] == b"ascii and null\x00"


@pytest.mark.parametrize("failure", [None, "missing", "malformed", "search", "backup"])
def test_module_partial_evidence_and_backup(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(daclread, "NXC_PATH", tmp_path)
    if failure == "backup":
        (tmp_path / "logs").write_text("not a directory")
    raw = b"bad" if failure == "malformed" else descriptor([ace(1), ace(0)])
    conn = SimpleNamespace(host="offline.invalid", search=Mock(return_value=[entry(None if failure == "missing" else raw)]), last_search_error="partial search" if failure == "search" else None)
    module = daclread.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"TARGET": "target*)(x=*", "ACTION": "backup"})
    result = module.on_login(context, conn)
    validate_module_result(module, result, "ldap", conn.host)
    assert result.status is (ResultStatus.SUCCESS if failure is None else ResultStatus.FAILED)
    assert "target\\2a\\29\\28x=\\2a" in conn.search.call_args.args[0]
    record = result.data.objects[0]
    if failure in (None, "search", "backup"):
        assert record["matches"] == [1]
        assert len(record["descriptor"]["aces"]) == 2
    if failure == "malformed":
        assert record["descriptor"]["raw"] == raw
    if failure is None:
        backup = json.loads(result.artifacts[0].path.read_text())
        assert bytes.fromhex(backup["sd"]) == raw
        assert result.artifacts[0].path.is_relative_to(tmp_path)


def test_missing_target_is_negative():
    module = daclread.NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"TARGET": "missing"})
    conn = SimpleNamespace(host="offline.invalid", search=Mock(return_value=[]), last_search_error=None)
    result = module.on_login(context, conn)
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.missing_targets == ["missing"]


@pytest.mark.parametrize(("right", "mask", "guid", "expected"), [
    ("FullControl", 0xF01FF, None, True),
    ("FullControl", 0x40000, None, False),
    ("DCSync", 0x100, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", True),
    ("DCSync", 0x100, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", True),
    ("ResetPassword", 0x100, "bf9679c0-0de6-11d0-a285-00aa003049e2", False),
])
def test_right_filters_are_numeric_and_guid_based(right, mask, guid, expected):
    module = daclread.NXCModule()
    module.options(SimpleNamespace(log=Mock()), {"TARGET": "target", "RIGHTS": right})
    record = descriptor_evidence(descriptor([ace(5 if guid else 0, mask=mask, guid=guid)]))["aces"][0]
    assert module.matches(record, "S-1-5-21-1-2-3-1100") is expected
    assert not module.matches(record, "S-1-5-21-1-2-3-9999")


def test_distinguished_name_search_uses_base_scope_and_restores_it():
    from impacket.ldap.ldapasn1 import Scope

    target = "CN=ESC4,CN=Certificate Templates,CN=Configuration,DC=example,DC=test"
    module = daclread.NXCModule()
    module.options(SimpleNamespace(log=Mock()), {"TARGET_DN": target, "PRINCIPAL_SID": "S-1-5-7"})
    connection = SimpleNamespace(host="offline.invalid", scope=Scope("wholeSubtree"), last_search_error=None)

    def search(search_filter, attributes, **kwargs):
        assert search_filter == "(objectClass=*)"
        assert kwargs["baseDN"] == target
        assert connection.scope == Scope("baseObject")
        return [entry(descriptor([ace()]))]

    connection.search = Mock(side_effect=search)
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    assert connection.scope == Scope("wholeSubtree")
    assert result.data.principal_sid == "S-1-5-7"
    assert result.data.missing_targets == []
    connection.search.assert_called_once()


def test_base_scope_restored_when_directory_reports_a_partial_error():
    from impacket.ldap.ldapasn1 import Scope

    module = daclread.NXCModule()
    module.options(SimpleNamespace(log=Mock()), {"TARGET_DN": "DC=example,DC=test"})
    connection = SimpleNamespace(host="offline.invalid", scope=Scope("wholeSubtree"), last_search_error="sizeLimitExceeded", search=Mock(return_value=[entry(descriptor())]))
    result = module.on_login(SimpleNamespace(log=Mock()), connection)
    assert connection.scope == Scope("wholeSubtree")
    assert result.status is ResultStatus.FAILED
    assert result.data.objects[0]["descriptor"] is not None


def test_built_in_sid_and_principal_name_are_mutually_exclusive():
    module = daclread.NXCModule()
    with pytest.raises(SystemExit):
        module.options(SimpleNamespace(log=Mock()), {"TARGET": "target", "PRINCIPAL": "alice", "PRINCIPAL_SID": "S-1-5-7"})
