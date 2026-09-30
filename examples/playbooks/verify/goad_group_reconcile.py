"""Correlate GOAD group inventories by SID and export a membership graph.

This reads saved results; it makes no network requests. Directory membership
paths are candidates for token privileges, not verified Windows access tokens.
"""

import argparse
import json
from collections import defaultdict, deque
from pathlib import Path

from nxc.paths import NXC_PATH


def load_inventory(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or len(document.get("hosts", [])) != 1:
        raise ValueError(f"Expected one version-1 host run in {path}")
    host = document["hosts"][0]
    summaries = [result for result in host["results"] if result["action"] == "goad_group_inventory"]
    if len(summaries) != 1 or summaries[0]["kind"] != "typed":
        raise ValueError(f"Expected one typed GOAD group summary in {path}")
    return host, summaries[0]["data"]


def shortest_membership_path(start, finish, adjacency):
    queue = deque([(start, [])])
    visited = {start}
    while queue:
        current, path = queue.popleft()
        if current == finish:
            return path
        for target, edge_index in adjacency[current]:
            if target not in visited:
                visited.add(target)
                queue.append((target, [*path, edge_index]))
    return None


def reconcile(paths):
    inventories = []
    for path in paths:
        host, data = load_inventory(path)
        if data["source_count"] != len(data["edges"]):
            raise ValueError(f"Source count does not match recorded edges in {path}")
        inventories.append((path, host, data))
    domains = [data["domain"] for _, _, data in inventories]
    if len(domains) != len(set(domains)) or len({data["manifest_sha256"] for _, _, data in inventories}) != 1:
        raise ValueError("Each domain needs one inventory from the same source snapshot")
    identities = {}
    nodes = {}
    for _path, _, data in inventories:
        domain = data["domain"]
        for edge in data["edges"]:
            group_sid = edge.get("group_sid")
            if group_sid:
                identities[domain, edge["group"].casefold()] = group_sid
                nodes[group_sid] = {"sid": group_sid, "domain": domain, "name": edge["group"], "kind": "group"}
            member_sid = edge.get("member_sid")
            if member_sid and edge["member_domain"] == domain:
                identities[domain, edge["member"].casefold()] = member_sid
                nodes.setdefault(member_sid, {"sid": member_sid, "domain": domain, "name": edge["member"], "kind": "group" if edge["source_kind"] == "nested_group" else "user"})
    edges = []
    unresolved = []
    for path, host, data in inventories:
        for source_index, item in enumerate(data["edges"]):
            status = item["status"]
            member_sid = item.get("member_sid")
            if status == "pending_sid_correlation":
                member_sid = identities.get((item["member_domain"], item["member"].casefold()))
                status = "observed_cross_domain" if member_sid and member_sid in item["foreign_sids"] else "foreign_sid_unresolved"
            if not status.startswith("observed") or not member_sid or not item.get("group_sid"):
                unresolved.append({"domain": data["domain"], "source_index": source_index, "status": status, "member": item["member"], "group": item["group"], "expected_sid": member_sid, "foreign_sids": item["foreign_sids"]})
                continue
            edges.append({"member_sid": member_sid, "group_sid": item["group_sid"], "member": item["member"], "member_domain": item["member_domain"], "group": item["group"], "group_domain": data["domain"], "kind": item["source_kind"], "status": status, "evidence": {"file": path.name, "root_target": host["target"], "source_index": source_index, "group_result_index": item["group_result_index"]}})
    adjacency = defaultdict(list)
    for index, edge in enumerate(edges):
        adjacency[edge["member_sid"]].append((edge["group_sid"], index))
    domain_admin_paths = []
    for sid, node in nodes.items():
        if node["kind"] != "user":
            continue
        for (domain, name), group_sid in identities.items():
            if name != "domain admins":
                continue
            path = shortest_membership_path(sid, group_sid, adjacency)
            if path is not None:
                domain_admin_paths.append({"user_sid": sid, "user": node["name"], "user_domain": node["domain"], "target_sid": group_sid, "target_domain": domain, "edge_indices": path})
    return {"schema_version": 1, "manifest_sha256": inventories[0][2]["manifest_sha256"], "source_count": sum(data["source_count"] for _, _, data in inventories), "verified_count": len(edges), "cross_domain_count": sum(edge["status"] == "observed_cross_domain" for edge in edges), "nodes": list(nodes.values()), "edges": edges, "unresolved": unresolved, "domain_admin_membership_paths": domain_admin_paths, "privilege_transitions_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Join saved GOAD group inventories by live SIDs")
    parser.add_argument("results", type=Path, nargs="+", help="One group-inventory JSON file per domain")
    parser.add_argument("--output", type=Path, default=Path(NXC_PATH) / "playbooks" / "goad-membership-graph.json")
    args = parser.parse_args(argv)
    result = reconcile(args.results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {result['verified_count']}/{result['source_count']} verified membership edges to {args.output}")
    return 0 if not result["unresolved"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
