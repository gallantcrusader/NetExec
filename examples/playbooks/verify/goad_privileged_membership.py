"""Verify the graph's domain-admin user paths with computed tokenGroups.

Run separately on each of the three GOAD domain controllers. This does not
construct a full logon token or change directory membership.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, ResultStatus


@dataclass
class PrivilegedMembership:
    domain: str
    manifest_sha256: str
    expected_count: int
    verified_count: int = 0
    missing_count: int = 0
    failed_count: int = 0
    paths: list[dict] = field(default_factory=list)
    transitions_executed: bool = False


def run(host):
    graph = json.loads((Path(NXC_PATH) / "playbooks" / "goad-membership-graph.json").read_text(encoding="utf-8"))
    controllers = {"10.60.0.10": "sevenkingdoms.local", "10.60.0.11": "north.sevenkingdoms.local", "10.60.0.12": "essos.local"}
    if host.target not in controllers or graph["unresolved"] or graph["verified_count"] != graph["source_count"]:
        raise ValueError("Start on a configured DC with a fully reconciled GOAD group graph")
    domain = controllers[host.target]
    paths = [path for path in graph["domain_admin_membership_paths"] if path["user_domain"] == domain and path["target_domain"] == domain]
    data = PrivilegedMembership(domain, graph["manifest_sha256"], len(paths))
    ldap = host.ldap()
    if not ldap.ok:
        return
    for path in paths:
        result = ldap.module("token-groups", principal=path["user"], stop_on_error=False)
        item = {"user": path["user"], "user_sid": path["user_sid"], "domain_admins_sid": path["target_sid"], "membership_edge_indices": path["edge_indices"], "token_result_index": len(host.run.results) - 1, "status": "unverified"}
        data.paths.append(item)
        if result.status is ResultStatus.FAILED:
            item["status"] = "lookup_failed"
            data.failed_count += 1
        elif result.ok and result.data.groups_returned and result.data.principal_sid == path["user_sid"] and path["target_sid"] in result.data.directory_sids:
            item["status"] = "computed_membership_confirmed"
            data.verified_count += 1
        else:
            item["status"] = "computed_membership_missing"
            data.missing_count += 1
    status = ResultStatus.FAILED if data.failed_count else ResultStatus.SUCCESS if data.verified_count == data.expected_count else ResultStatus.NEGATIVE
    error = f"{data.failed_count} computed membership lookups failed" if data.failed_count else None
    host.record(ActionResult("ldap", "goad_privileged_membership", host.target, status, data, error=error), stop_on_error=False)
