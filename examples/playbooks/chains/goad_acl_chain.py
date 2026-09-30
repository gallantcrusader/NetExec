"""Collect the configured Sevenkingdoms ACL chain as candidate-path evidence.

This checks direct ACEs and assesses user DACLs under explicit SID assumptions.
It does not execute transitions. Full ordered descriptors remain in results.
"""

from dataclasses import dataclass, field

from nxc.playbooks.access import assess_dacl
from nxc.playbooks.results import ActionResult, ResultStatus


@dataclass
class ChainEvidence:
    edges: list[dict] = field(default_factory=list)
    candidate_chain_present: bool = False
    transitions_executed: bool = False


def run(host):
    if host.target != "10.60.0.10":
        raise ValueError("This GOAD ACL-chain playbook expects Kingslanding at 10.60.0.10")
    ldap = host.ldap()
    if not ldap.ok:
        return
    member = "bf9679c0-0de6-11d0-a285-00aa003049e2"
    chain = [
        ("tywin.lannister", "jaime.lannister", "ResetPassword", (0x100,), "00299570-246d-11d0-a768-00aa006e0529"),
        ("jaime.lannister", "joffrey.baratheon", "GenericWrite", (0x20028, 0x40000000), None),
        ("joffrey.baratheon", "tyron.lannister", "WriteDacl", (0x40000,), None),
        ("tyron.lannister", "Small Council", "SelfMembership", (0x8,), member),
        ("Small Council", "DragonStone", "WriteMembers", (0x20,), member),
        ("DragonStone", "KingsGuard", "WriteOwner", (0x80000,), None),
        ("KingsGuard", "stannis.baratheon", "GenericAll", (0xF01FF, 0x10000000), None),
        ("stannis.baratheon", "kingslanding$", "GenericAll", (0xF01FF, 0x10000000), None),
    ]
    data = ChainEvidence()
    for principal, target, right, masks, guid in chain:
        result = ldap.module("daclread", target=target, principal=principal, ace_type="all")
        matching = []
        for obj in result.data.objects:
            for index in obj["matches"]:
                ace = obj["descriptor"]["aces"][index]
                if ace["access"] == "allowed" and not ace["inherit_only"] and ace["object_type"] == guid and any(ace["mask"] & mask == mask for mask in masks):
                    matching.append({"dn": obj["dn"], "ace_index": index})
        edge = {"principal": principal, "principal_sid": result.data.principal_sid, "target": target, "right": right, "matching_aces": matching, "assessments": []}
        data.edges.append(edge)
        if principal in {"Small Council", "DragonStone", "KingsGuard"}:
            edge["assessment_limit"] = "Group edge requires the token after the preceding membership transition"
            continue
        groups = ldap.module("token-groups", principal=principal)
        if not groups.ok or not groups.data.groups_returned:
            edge["assessment_limit"] = "Computed directory groups unavailable"
            continue
        # These are explicit assumptions about an authenticated network logon;
        # tokenGroups itself is directory evidence, not a complete Windows token.
        edge["assumed_logon_sids"] = ["S-1-1-0", "S-1-5-11", "S-1-5-2"]
        edge["directory_sids"] = groups.data.directory_sids
        for obj in result.data.objects:
            edge["assessments"].append({"dn": obj["dn"], "dacl": assess_dacl(obj["descriptor"], [*groups.data.directory_sids, *edge["assumed_logon_sids"]], masks[0], object_type=guid, target_sid=obj["sid"])})
    data.candidate_chain_present = all(edge["matching_aces"] for edge in data.edges)
    host.record(ActionResult("ldap", "goad_acl_chain", host.target, ResultStatus.SUCCESS if data.candidate_chain_present else ResultStatus.NEGATIVE, data))
