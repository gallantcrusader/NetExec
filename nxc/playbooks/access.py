"""Ordered AD DACL assessment for supplied SIDs, with explicit unsupported cases.

This does not construct a Windows token or evaluate privileges, trust filtering,
restricted tokens, SACL policy, or directory-operation-specific constraints.
"""

from dataclasses import dataclass, field


@dataclass
class DACLAssessment:
    decision: str
    requested_mask: int
    remaining_mask: int
    reason: str
    ace_indices: list[int] = field(default_factory=list)


def map_directory_mask(mask):
    for generic, specific in ((0x10000000, 0xF01FF), (0x80000000, 0x20094), (0x40000000, 0x20028), (0x20000000, 0x20004)):
        if mask & generic:
            mask = (mask & ~generic) | specific
    return mask


def assess_dacl(descriptor, token_sids, requested_mask, *, object_type=None, target_sid=None, deny_only_sids=()):
    """Assess the DACL using caller-supplied enabled/deny-only SIDs.

    An allowed result is conditional on the supplied SID sets and the supported
    semantics here. Callers must retain those assumptions with the evidence.
    """
    requested = map_directory_mask(requested_mask)
    result = DACLAssessment("unknown", requested, requested, "")
    if requested <= 0 or requested & ~0xF01FF:
        result.reason = "Requested mask includes unsupported or no directory rights"
        return result
    if not isinstance(descriptor.get("dacl_present"), bool) or not isinstance(descriptor.get("null_dacl"), bool) or not isinstance(descriptor.get("aces"), list):
        result.reason = "Descriptor evidence is incomplete"
        return result
    deny_only = set(deny_only_sids)
    enabled = set(token_sids) - deny_only
    denied = enabled | deny_only
    if not descriptor.get("dacl_present") or descriptor.get("null_dacl"):
        result.decision, result.remaining_mask, result.reason = "allowed", 0, "No discretionary ACL restricts access"
        return result
    if descriptor.get("owner_sid") in enabled and requested & 0x60000:
        result.reason = "Owner implicit rights/OWNER RIGHTS semantics require a full token access check"
        return result
    for ace in descriptor["aces"]:
        if ace["flags"] & 8:
            continue
        if not ace["supported"]:
            result.reason = "Unsupported ACE may affect the remaining rights"
            result.ace_indices.append(ace["index"])
            return result
        trustee = target_sid if ace["trustee_sid"] == "S-1-5-10" else ace["trustee_sid"]
        relevant = map_directory_mask(ace["mask"]) & result.remaining_mask
        if not relevant:
            continue
        if ace["trustee_sid"] == "S-1-3-4":
            result.reason = "OWNER RIGHTS requires a full token ownership check"
            return result
        if trustee is None:
            result.reason = "Principal SELF requires the target object's SID"
            return result
        if trustee not in (denied if ace["access"] == "denied" else enabled):
            continue
        if ace["object_type"] is not None and ace["object_type"] != object_type:
            if relevant & 0x30:
                result.reason = "Object/property-set GUID scope is unresolved"
                result.ace_indices.append(ace["index"])
                return result
            # Standard rights with an object GUID need object-type-list semantics.
            if relevant & 0xF0000:
                result.reason = "Object-specific standard rights require an object-type access check"
                return result
            continue
        result.ace_indices.append(ace["index"])
        if ace["access"] == "denied":
            result.decision, result.reason = "denied", "Ordered deny ACE rejects remaining requested rights"
            return result
        result.remaining_mask &= ~relevant
        if not result.remaining_mask:
            result.decision, result.reason = "allowed", "Ordered allow ACEs satisfy the requested rights for the supplied SIDs"
            return result
    result.decision, result.reason = "denied", "DACL did not grant all requested rights for the supplied SIDs"
    return result
