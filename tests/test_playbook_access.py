"""Ordered DACL evaluation under explicitly supplied token assumptions."""

import pytest

from nxc.playbooks.access import assess_dacl, map_directory_mask


def entry(index, access="allowed", sid="user", mask=0x40000, flags=0, guid=None):
    return {"index": index, "supported": True, "access": access, "trustee_sid": sid, "mask": mask, "flags": flags, "object_type": guid}


def descriptor(*aces):
    return {"dacl_present": True, "null_dacl": False, "owner_sid": "owner", "aces": list(aces)}


def test_order_and_remaining_bits():
    allow = entry(0)
    deny = entry(1, "denied")
    assert assess_dacl(descriptor(allow, deny), ["user"], 0x40000).decision == "allowed"
    assert assess_dacl(descriptor(deny, allow), ["user"], 0x40000).decision == "denied"
    result = assess_dacl(descriptor(allow, entry(1, mask=0x80000)), ["user"], 0xc0000)
    assert result.decision == "allowed"
    assert result.ace_indices == [0, 1]
    assert result.remaining_mask == 0


def test_deny_only_group_cannot_grant_but_can_deny():
    assert assess_dacl(descriptor(entry(0, sid="group")), ["user"], 0x40000, deny_only_sids=["group"]).decision == "denied"
    assert assess_dacl(descriptor(entry(0, sid="group")), ["user", "group"], 0x40000, deny_only_sids=["group"]).decision == "denied"
    assert assess_dacl(descriptor(entry(0, "denied", sid="group"), entry(1)), ["user"], 0x40000, deny_only_sids=["group"]).decision == "denied"


def test_inherit_only_and_unrelated_sid_are_ignored():
    assert assess_dacl(descriptor(entry(0, flags=8), entry(1, sid="other")), ["user"], 0x40000).decision == "denied"


@pytest.mark.parametrize("descriptor_data", [{}, {"raw": b"broken"}])
def test_incomplete_descriptor_never_grants_access(descriptor_data):
    assert assess_dacl(descriptor_data, ["user"], 0x40000).decision == "unknown"


def test_owner_and_unknown_ace_do_not_fabricate_effective_access():
    assert assess_dacl(descriptor(entry(0, sid="owner")), ["owner"], 0x40000).decision == "unknown"
    assert assess_dacl(descriptor({"index": 0, "supported": False, "flags": 0}, entry(1)), ["user"], 0x40000).decision == "unknown"
    assert assess_dacl(descriptor(entry(0, sid="S-1-3-4"), entry(1)), ["user"], 0x40000).decision == "unknown"


def test_object_guid_and_property_set_ambiguity():
    ace = entry(0, mask=0x100, guid="reset-password")
    assert assess_dacl(descriptor(ace), ["user"], 0x100, object_type="reset-password").decision == "allowed"
    assert assess_dacl(descriptor(ace), ["user"], 0x100, object_type="other").decision == "denied"
    assert assess_dacl(descriptor(entry(0, mask=0x20, guid="property-set")), ["user"], 0x20, object_type="member").decision == "unknown"


def test_principal_self_and_generic_mapping():
    assert assess_dacl(descriptor(entry(0, sid="S-1-5-10")), ["user"], 0x40000, target_sid="user").decision == "allowed"
    assert assess_dacl(descriptor(entry(0, sid="S-1-5-10")), ["user"], 0x40000).decision == "unknown"
    assert map_directory_mask(0x40000000) == 0x20028
    assert assess_dacl(descriptor(entry(0, mask=0x10000000)), ["user"], 0x40000).decision == "allowed"


def test_null_and_empty_dacl_are_distinct():
    assert assess_dacl({"dacl_present": True, "null_dacl": True, "aces": []}, ["user"], 0x40000).decision == "allowed"
    assert assess_dacl(descriptor(), ["user"], 0x40000).decision == "denied"
