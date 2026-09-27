"""Reconcile every configured GOAD ACL entry with live ordered DACL evidence.

The manifest contains the 22 ACL entries in the deployed GOAD config, without
secrets. This records direct grants and unresolved entries; it does not perform
an access check or execute any directory changes.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from nxc.playbooks.access import assess_dacl, map_directory_mask
from nxc.playbooks.results import ActionResult, ResultStatus


RIGHTS = {
    "GenericAll": (0xF01FF, None),
    "GenericWrite": (0x20028, None),
    "WriteDacl": (0x40000, None),
    "WriteOwner": (0x80000, None),
    "WriteProperty": (0x20, None),
    "ReadProperty": (0x10, None),
    "GenericExecute": (0x20004, None),
    "Ext-User-Force-Change-Password": (0x100, "00299570-246d-11d0-a768-00aa006e0529"),
    "Ext-Self-Self-Membership": (0x8, "bf9679c0-0de6-11d0-a285-00aa003049e2"),
    "Ext-Write-Self-Membership": (0x20, "bf9679c0-0de6-11d0-a285-00aa003049e2"),
}


@dataclass
class ACLInventory:
    domain: str
    manifest_sha256: str
    source_count: int = 0
    observed_count: int = 0
    failed_count: int = 0
    assessed_count: int = 0
    assessed_allowed: int = 0
    assessed_denied: int = 0
    assessed_unknown: int = 0
    edges: list[dict] = field(default_factory=list)
    transitions_executed: bool = False


def matches_expected(ace, sid, right):
    mask, guid = RIGHTS[right]
    return (
        ace.get("supported") and ace.get("access") == "allowed"
        and ace.get("trustee_sid") == sid and not ace.get("inherit_only")
        and ace.get("object_type") == guid
        and map_directory_mask(ace["mask"]) & mask == mask
    )


def run(host):
    manifest = json.loads((Path(__file__).with_name("goad_acl_manifest.json")).read_text(encoding="utf-8"))
    selection = [(name, spec) for name, spec in manifest["domains"].items() if spec["dc"] == host.target]
    if len(selection) != 1:
        raise ValueError("Start on exactly one configured GOAD domain controller")
    domain, domain_spec = selection[0]
    unknown = {item["right"] for item in domain_spec["acls"]} - RIGHTS.keys()
    if unknown:
        raise ValueError(f"Unmapped configured ACL right(s): {', '.join(sorted(unknown))}")
    data = ACLInventory(domain, manifest["source_sha256"], len(domain_spec["acls"]))
    ldap = host.ldap()
    if not ldap.ok:
        return
    group_cache = {}
    for item in domain_spec["acls"]:
        principal = item["for"]
        target = item["to"]
        options = {"target_dn" if target.lower().startswith(("cn=", "ou=", "dc=")) else "target": target, "ace_type": "all"}
        if principal == "NT AUTHORITY\\ANONYMOUS LOGON":
            options["principal_sid"] = "S-1-5-7"
        else:
            options["principal"] = principal
        result = ldap.module("daclread", stop_on_error=False, **options)
        edge = {"name": item["name"], "principal": principal, "principal_kind": item["principal_kind"], "principal_sid": getattr(result.data, "principal_sid", None), "target": target, "right": item["right"], "inheritance": item["inheritance"], "dacl_result_index": len(host.run.results) - 1, "matching_aces": [], "assessments": [], "status": "unresolved"}
        data.edges.append(edge)
        if result.status is ResultStatus.FAILED:
            edge["status"] = "failed"
            edge["error"] = result.error
            data.failed_count += 1
            continue
        for obj in result.data.objects:
            for index in obj["matches"]:
                ace = obj["descriptor"]["aces"][index]
                if matches_expected(ace, result.data.principal_sid, item["right"]):
                    edge["matching_aces"].append({"dn": obj["dn"], "ace_index": index, "mask": ace["mask"], "object_type": ace["object_type"], "inherited": ace["inherited"]})
        if edge["matching_aces"]:
            edge["status"] = "observed"
            data.observed_count += 1
        elif result.data.missing_targets:
            edge["status"] = "target_missing"
        if item["principal_kind"] != "user":
            edge["assessment_limit"] = "A live token for this principal type was not constructed"
            continue
        if principal not in group_cache:
            group_cache[principal] = (ldap.module("token-groups", principal=principal, stop_on_error=False), len(host.run.results) - 1)
        groups, group_result_index = group_cache[principal]
        edge["group_result_index"] = group_result_index
        if not groups.ok or not getattr(groups.data, "groups_returned", False):
            edge["assessment_limit"] = "Computed directory groups were unavailable"
            continue
        edge["directory_sids"] = groups.data.directory_sids
        edge["assumed_logon_sids"] = ["S-1-1-0", "S-1-5-11", "S-1-5-2"]
        mask, guid = RIGHTS[item["right"]]
        for obj in result.data.objects:
            assessment = assess_dacl(obj["descriptor"], [*groups.data.directory_sids, *edge["assumed_logon_sids"]], mask, object_type=guid, target_sid=obj["sid"])
            edge["assessments"].append({"dn": obj["dn"], "dacl": assessment})
            data.assessed_count += 1
            if assessment.decision == "allowed":
                data.assessed_allowed += 1
            elif assessment.decision == "denied":
                data.assessed_denied += 1
            else:
                data.assessed_unknown += 1
    status = ResultStatus.FAILED if data.failed_count else ResultStatus.SUCCESS if data.observed_count == data.source_count else ResultStatus.NEGATIVE
    error = f"{data.failed_count} configured ACL lookups failed" if data.failed_count else None
    host.record(ActionResult("ldap", "goad_acl_inventory", host.target, status, data, error=error), stop_on_error=False)
