"""Join saved GOAD directory and host-group evidence by SID.

This is offline path discovery. A route through membership does not establish
that an account can log on to a host or use a specific privileged operation.
"""

import argparse
import json
from collections import defaultdict, deque
from pathlib import Path

from nxc.paths import NXC_PATH


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


def load_host(path, expected_target, source_sha256):
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or len(document.get("hosts", [])) != 1:
        raise ValueError(f"Expected one version-1 host run in {path}")
    host = document["hosts"][0]
    summaries = [result for result in host["results"] if result["action"] == "goad_local_group_inventory"]
    if host["target"] != expected_target or len(summaries) != 1 or summaries[0]["kind"] != "typed":
        raise ValueError(f"Unexpected host or missing typed local group summary in {path}")
    data = summaries[0]["data"]
    if data["manifest_sha256"] != source_sha256 or data["source_count"] != len(data["edges"]):
        raise ValueError(f"Source snapshot or edge count does not match in {path}")
    return host, data


def reachability(graph, manifest, host_files):
    if graph["manifest_sha256"] != manifest["source_sha256"]:
        raise ValueError("Directory graph and host manifest use different source snapshots")
    if graph["unresolved"] or graph["source_count"] != graph["verified_count"]:
        raise ValueError("Directory membership graph has unresolved source edges")
    if set(host_files) != set(manifest["hosts"]):
        raise ValueError("Provide one saved local-group inventory for every configured host")
    directory_nodes = {node["sid"]: node for node in graph["nodes"]}
    adjacency = defaultdict(list)
    for index, edge in enumerate(graph["edges"]):
        adjacency[edge["member_sid"]].append((edge["group_sid"], index))
    host_edges = []
    unresolved = []
    for target, host_source in manifest["hosts"].items():
        path = host_files[target]
        host, data = load_host(path, target, manifest["source_sha256"])
        if data["source_count"] != sum(len(members) for members in host_source["local_groups"].values()):
            raise ValueError(f"Local-group source count mismatch for {target}")
        unresolved.extend({"target": target, **source_edge} for source_edge in data["edges"] if source_edge["status"] != "observed" or not source_edge.get("member_sid"))
        for group_name in host_source["local_groups"]:
            matching = [edge for edge in data["edges"] if edge["group"] == group_name]
            indices = {edge["result_index"] for edge in matching}
            if len(indices) != 1:
                raise ValueError(f"Expected one SAMR result for {target} {group_name}")
            result_index = indices.pop()
            result = host["results"][result_index]
            if result["action"] != "local_groups" or result["status"] != "success":
                unresolved.append({"target": target, "group": group_name, "status": "samr_result_unavailable"})
                continue
            source_sids = {edge["member_sid"] for edge in matching if edge["status"] == "observed"}
            for sid, name in result["data"]["members"].items():
                node = directory_nodes.get(sid)
                host_edges.append({"target": target, "hostname": host_source["name"], "group": group_name, "member_sid": sid, "member_name": name, "directory_identity": node, "configured": sid in source_sids, "evidence": {"file": path.name, "result_index": result_index}})
    routes = []
    for node in directory_nodes.values():
        if node["kind"] != "user":
            continue
        for host_index, edge in enumerate(host_edges):
            path = shortest_membership_path(node["sid"], edge["member_sid"], adjacency)
            if path is not None:
                routes.append({"user": node["name"], "user_domain": node["domain"], "user_sid": node["sid"], "target": edge["target"], "hostname": edge["hostname"], "local_group": edge["group"], "alias_member_sid": edge["member_sid"], "alias_member_name": edge["member_name"], "directory_edge_indices": path, "host_edge_index": host_index, "status": "membership_route_observed"})
    return {"schema_version": 1, "manifest_sha256": graph["manifest_sha256"], "directory_edge_count": len(graph["edges"]), "host_edge_count": len(host_edges), "configured_host_edge_count": sum(edge["configured"] for edge in host_edges), "host_edges": host_edges, "routes": routes, "unresolved": unresolved, "route_enumeration": "one shortest directory-membership path per user and observed host-alias member", "logons_tested": False, "privilege_transitions_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Join saved GOAD directory and local-group evidence")
    parser.add_argument("graph", type=Path)
    parser.add_argument("host_results", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, default=Path(NXC_PATH) / "playbooks" / "goad-host-reachability.json")
    args = parser.parse_args(argv)
    manifest = json.loads(Path(__file__).with_name("goad_membership_manifest.json").read_text(encoding="utf-8"))
    host_files = {}
    for path in args.host_results:
        document = json.loads(path.read_text(encoding="utf-8"))
        if len(document.get("hosts", [])) != 1:
            raise ValueError(f"Expected one host run in {path}")
        target = document["hosts"][0]["target"]
        if target in host_files:
            raise ValueError(f"Duplicate host inventory for {target}")
        host_files[target] = path
    result = reachability(json.loads(args.graph.read_text(encoding="utf-8")), manifest, host_files)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(result['routes'])} candidate routes through {result['host_edge_count']} observed host-group members to {args.output}")
    return 0 if not result["unresolved"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
