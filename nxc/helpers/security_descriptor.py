"""Lossless descriptor evidence with decoded standard and object access ACEs."""

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string


def descriptor_evidence(raw):
    descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
    dacl = descriptor["Dacl"] if descriptor["OffsetDacl"] else None
    result = {
        "raw": raw, "control": descriptor["Control"],
        "owner_sid": descriptor["OwnerSid"].formatCanonical() if descriptor["OwnerSid"] else None,
        "group_sid": descriptor["GroupSid"].formatCanonical() if descriptor["GroupSid"] else None,
        "dacl_present": bool(descriptor["Control"] & 4),
        "null_dacl": bool(descriptor["Control"] & 4) and not bool(dacl),
        "aces": [],
    }
    if not dacl:
        return result
    for index, ace in enumerate(dacl.aces):
        entry = {"index": index, "type": ace["TypeName"], "type_id": ace["AceType"], "flags": ace["AceFlags"], "raw": ace.getData(), "supported": ace["AceType"] in (0, 1, 5, 6)}
        result["aces"].append(entry)
        if not entry["supported"]:
            continue
        body = ace["Ace"]
        entry.update({
            "access": "allowed" if ace["AceType"] in (0, 5) else "denied",
            "mask": body["Mask"]["Mask"], "trustee_sid": body["Sid"].formatCanonical(),
            "inherited": bool(ace["AceFlags"] & 16), "inherit_only": bool(ace["AceFlags"] & 8),
            "object_flags": body["Flags"] if ace["AceType"] in (5, 6) else 0,
            "object_type": None, "inherited_object_type": None,
        })
        if ace["AceType"] in (5, 6):
            if body["Flags"] & 1:
                entry["object_type"] = bin_to_string(body["ObjectType"]).lower()
            if body["Flags"] & 2:
                entry["inherited_object_type"] = bin_to_string(body["InheritedObjectType"]).lower()
    return result
