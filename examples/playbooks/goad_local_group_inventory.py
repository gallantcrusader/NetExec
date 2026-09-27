"""Compare configured GOAD host local groups with live SAMR membership.

Run once per configured host with an account allowed to read its local groups.
This only enumerates aliases and their members; it changes no membership.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from nxc.playbooks.results import ActionResult, ResultStatus


@dataclass
class LocalGroupInventory:
    hostname: str
    domain: str
    manifest_sha256: str
    source_count: int
    observed_count: int = 0
    missing_count: int = 0
    failed_count: int = 0
    edges: list[dict] = field(default_factory=list)
    transitions_executed: bool = False


def member_matches(expected, observed):
    expected_domain, expected_name = expected.split("\\", 1)
    observed_parts = observed.split("\\", 1)
    if len(observed_parts) == 1:
        return expected_name.casefold() == observed.casefold()
    return expected_domain.casefold() == observed_parts[0].casefold() and expected_name.casefold() == observed_parts[1].casefold()


def run(host):
    manifest = json.loads(Path(__file__).with_name("goad_membership_manifest.json").read_text(encoding="utf-8"))
    if host.target not in manifest["hosts"]:
        raise ValueError("Start on a configured GOAD host")
    source = manifest["hosts"][host.target]
    expected = [(group, member) for group, members in source["local_groups"].items() for member in members]
    data = LocalGroupInventory(source["name"], source["domain"], manifest["source_sha256"], len(expected))
    smb = host.smb()
    if not smb.ok:
        return
    cached = {}
    for group_name, member_name in expected:
        if group_name not in cached:
            cached[group_name] = (smb.local_groups(local_groups=group_name, stop_on_error=False), len(host.run.results) - 1)
        result, result_index = cached[group_name]
        edge = {"group": group_name, "member": member_name, "member_sid": None, "observed_name": None, "result_index": result_index, "status": "unresolved"}
        data.edges.append(edge)
        if result.status is ResultStatus.FAILED:
            edge["status"] = "lookup_failed"
            edge["error"] = result.error
            data.failed_count += 1
        else:
            matches = [(sid, name) for sid, name in result.data.members.items() if member_matches(member_name, name)]
            if len(matches) == 1:
                edge["member_sid"], edge["observed_name"] = matches[0]
                edge["status"] = "observed"
                data.observed_count += 1
            else:
                edge["status"] = "member_missing_or_ambiguous"
                data.missing_count += 1
    status = ResultStatus.FAILED if data.failed_count else ResultStatus.SUCCESS if data.observed_count == data.source_count else ResultStatus.NEGATIVE
    error = f"{data.failed_count} local group lookups failed" if data.failed_count else None
    host.record(ActionResult("smb", "goad_local_group_inventory", host.target, status, data, error=error), stop_on_error=False)
