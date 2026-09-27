"""Cross-domain identity correlation and host-local membership evidence."""

import json
import runpy
from pathlib import Path

import pytest

from nxc.playbooks.runner import load_playbook


ROOT = Path(__file__).parents[1] / "examples" / "playbooks"


def inventory(path, domain, target, edges, digest="same"):
    document = {"schema_version": 1, "hosts": [{"target": target, "results": [{"action": "goad_group_inventory", "kind": "typed", "data": {"domain": domain, "manifest_sha256": digest, "source_count": len(edges), "edges": edges}}]}]}
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def edge(member, member_domain, member_sid, group, group_sid, kind="user_group", status="observed", foreign_sids=None):
    return {"member": member, "member_domain": member_domain, "member_sid": member_sid, "group": group, "group_sid": group_sid, "source_kind": kind, "status": status, "foreign_sids": foreign_sids or [], "group_result_index": 1}


def test_foreign_sid_correlates_to_home_identity_and_nested_path(tmp_path):
    reconcile = runpy.run_path(str(ROOT / "goad_group_reconcile.py"))["reconcile"]
    home = inventory(tmp_path / "home.json", "home.local", "10.60.0.10", [
        edge("alice", "home.local", "S-A", "Team", "S-T"),
        edge("Team", "home.local", "S-T", "Domain Admins", "S-DA", kind="nested_group"),
    ])
    foreign = inventory(tmp_path / "foreign.json", "foreign.local", "10.60.0.12", [
        edge("alice", "home.local", None, "Visitors", "S-V", status="pending_sid_correlation", foreign_sids=["S-A"]),
    ])
    result = reconcile([home, foreign])
    assert result["verified_count"] == 3
    assert result["cross_domain_count"] == 1
    assert result["unresolved"] == []
    assert result["domain_admin_membership_paths"] == [{"user_sid": "S-A", "user": "alice", "user_domain": "home.local", "target_sid": "S-DA", "target_domain": "home.local", "edge_indices": [0, 1]}]


def test_foreign_sid_mismatch_stays_unresolved(tmp_path):
    reconcile = runpy.run_path(str(ROOT / "goad_group_reconcile.py"))["reconcile"]
    home = inventory(tmp_path / "home.json", "home.local", "10.60.0.10", [edge("alice", "home.local", "S-A", "Team", "S-T")])
    foreign = inventory(tmp_path / "foreign.json", "foreign.local", "10.60.0.12", [edge("alice", "home.local", None, "Visitors", "S-V", status="pending_sid_correlation", foreign_sids=["S-other"])])
    result = reconcile([home, foreign])
    assert result["verified_count"] == 1
    assert result["cross_domain_count"] == 0
    assert result["unresolved"][0]["status"] == "foreign_sid_unresolved"
    assert result["unresolved"][0]["expected_sid"] == "S-A"


def test_reconcile_rejects_mixed_source_snapshots(tmp_path):
    reconcile = runpy.run_path(str(ROOT / "goad_group_reconcile.py"))["reconcile"]
    first = inventory(tmp_path / "first.json", "one.local", "10.60.0.10", [], "one")
    second = inventory(tmp_path / "second.json", "two.local", "10.60.0.12", [], "two")
    with pytest.raises(ValueError, match="same source snapshot"):
        reconcile([first, second])


def test_samr_bare_names_match_configured_identity_without_assuming_domain():
    playbook = load_playbook(ROOT / "goad_local_group_inventory.py")
    module = __import__(playbook.__module__, fromlist=["member_matches"])
    assert module.member_matches("essos\\khal.drogo", "khal.drogo")
    assert module.member_matches("essos\\khal.drogo", "ESSOS\\KHAL.DROGO")
    assert not module.member_matches("essos\\khal.drogo", "NORTH\\khal.drogo")
    assert not module.member_matches("essos\\khal.drogo", "jorah.mormont")


def test_host_reachability_joins_samr_and_directory_sids(tmp_path):
    reachability = runpy.run_path(str(ROOT / "goad_host_reachability.py"))["reachability"]
    graph = {"manifest_sha256": "same", "source_count": 1, "verified_count": 1, "unresolved": [], "nodes": [
        {"sid": "S-user", "name": "alice", "domain": "home.local", "kind": "user"},
        {"sid": "S-group", "name": "Ops", "domain": "home.local", "kind": "group"},
    ], "edges": [{"member_sid": "S-user", "group_sid": "S-group"}]}
    manifest = {"source_sha256": "same", "hosts": {"10.60.0.10": {"name": "server", "local_groups": {"Administrators": ["home\\Ops"]}}}}
    document = {"schema_version": 1, "hosts": [{"target": "10.60.0.10", "results": [
        {"action": "local_groups", "status": "success", "data": {"members": {"S-group": "Ops", "S-other": "other"}}},
        {"action": "goad_local_group_inventory", "kind": "typed", "data": {"manifest_sha256": "same", "source_count": 1, "edges": [{"group": "Administrators", "member_sid": "S-group", "status": "observed", "result_index": 0}]}}
    ]}]}
    path = tmp_path / "host.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    result = reachability(graph, manifest, {"10.60.0.10": path})
    assert result["configured_host_edge_count"] == 1
    assert result["host_edge_count"] == 2
    assert [(item["user"], item["alias_member_sid"], item["directory_edge_indices"]) for item in result["routes"]] == [("alice", "S-group", [0])]
    assert result["logons_tested"] is False


def test_host_reachability_rejects_unresolved_directory_graph():
    reachability = runpy.run_path(str(ROOT / "goad_host_reachability.py"))["reachability"]
    with pytest.raises(ValueError, match="unresolved source edges"):
        reachability({"manifest_sha256": "same", "source_count": 1, "verified_count": 0, "unresolved": [{}]}, {"source_sha256": "same", "hosts": {}}, {})
