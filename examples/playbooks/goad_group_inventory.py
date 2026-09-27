"""Check the GOAD source's direct directory memberships against live LDAP data.

Foreign-security-principal SIDs remain pending until correlated with the home
domain. This playbook changes no directory object or group membership.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from nxc.playbooks.results import ActionResult, ResultStatus


@dataclass
class GroupInventory:
    domain: str
    manifest_sha256: str
    source_count: int
    observed_count: int = 0
    primary_count: int = 0
    pending_count: int = 0
    missing_count: int = 0
    failed_count: int = 0
    edges: list[dict] = field(default_factory=list)
    transitions_executed: bool = False


def names_for(member):
    return {str(member[key]).casefold() for key in ("sAMAccountName", "cn") if isinstance(member.get(key), str)}


def run(host):
    manifest = json.loads(Path(__file__).with_name("goad_membership_manifest.json").read_text(encoding="utf-8"))
    selected = [(name, entry) for name, entry in manifest["domains"].items() if entry["dc"] == host.target]
    if len(selected) != 1:
        raise ValueError("Start on exactly one configured GOAD domain controller")
    domain, entry = selected[0]
    data = GroupInventory(domain, manifest["source_sha256"], len(entry["memberships"]))
    ldap = host.ldap()
    if not ldap.ok:
        return
    cached = {}
    for source in entry["memberships"]:
        group_name = source["group"]
        if group_name not in cached:
            cached[group_name] = (ldap.groups(groups=group_name, stop_on_error=False), len(host.run.results) - 1)
        result, result_index = cached[group_name]
        edge = {**source, "group_result_index": result_index, "group_sid": None, "member_sid": None, "member_dn": None, "foreign_sids": [], "status": "unresolved"}
        data.edges.append(edge)
        if result.status is ResultStatus.FAILED:
            edge["status"] = "lookup_failed"
            edge["error"] = result.error
            data.failed_count += 1
            continue
        groups = result.data.groups
        if len(groups) != 1 or not isinstance(groups[0].get("objectSid"), str):
            edge["status"] = "group_missing_or_ambiguous"
            data.missing_count += 1
            continue
        edge["group_sid"] = groups[0]["objectSid"]
        direct = groups[0].get("member", [])
        direct_dns = {dn.casefold() for dn in (direct if isinstance(direct, list) else [direct]) if isinstance(dn, str)}
        if source["member_domain"] != domain:
            foreign = [member for member in result.data.members if "CN=ForeignSecurityPrincipals," in str(member.get("distinguishedName", "")) or "foreignSecurityPrincipal" in str(member.get("objectClass", ""))]
            edge["foreign_sids"] = [member["objectSid"] for member in foreign if isinstance(member.get("objectSid"), str)]
            edge["status"] = "pending_sid_correlation" if edge["foreign_sids"] else "member_missing"
            data.pending_count += edge["status"] == "pending_sid_correlation"
            data.missing_count += edge["status"] == "member_missing"
            continue
        expected = source["member"].casefold()
        matching = [member for member in result.data.members if expected in names_for(member)]
        if len(matching) != 1:
            edge["status"] = "member_missing_or_ambiguous"
            data.missing_count += 1
            continue
        member = matching[0]
        edge["member_sid"] = member.get("objectSid")
        edge["member_dn"] = member.get("distinguishedName")
        edge["status"] = "observed" if isinstance(edge["member_dn"], str) and edge["member_dn"].casefold() in direct_dns else "observed_primary"
        data.observed_count += 1
        data.primary_count += edge["status"] == "observed_primary"
    status = ResultStatus.FAILED if data.failed_count else ResultStatus.SUCCESS if data.observed_count == data.source_count else ResultStatus.NEGATIVE
    error = f"{data.failed_count} group lookups failed" if data.failed_count else None
    host.record(ActionResult("ldap", "goad_group_inventory", host.target, status, data, error=error), stop_on_error=False)
