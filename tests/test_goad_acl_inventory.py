"""The source ACL manifest and broad inventory preserve unmatched edges."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import load_playbook


SCRIPT = Path(__file__).parents[1] / "examples" / "playbooks" / "verify" / "goad_acl_inventory.py"
MANIFEST = SCRIPT.with_name("goad_acl_manifest.json")


def test_manifest_covers_every_configured_acl_family():
    document = json.loads(MANIFEST.read_text())
    assert document["source"] == "ad/GOAD/data/config.json"
    assert len(document["source_sha256"]) == 64
    assert {domain: len(spec["acls"]) for domain, spec in document["domains"].items()} == {"sevenkingdoms.local": 12, "north.sevenkingdoms.local": 2, "essos.local": 8}
    assert sum(len(spec["acls"]) for spec in document["domains"].values()) == 22
    assert any(item["to"].startswith("CN=ESC4") for item in document["domains"]["essos.local"]["acls"])
    assert all(item["principal_kind"] in {"user", "group", "gmsa", "well_known"} for spec in document["domains"].values() for item in spec["acls"])


@pytest.mark.parametrize(("right", "mask", "guid", "match"), [
    ("GenericAll", 0x10000000, None, True),
    ("GenericAll", 0x40000, None, False),
    ("GenericWrite", 0x40000000, None, True),
    ("GenericWrite", 0x20028, "member-guid", False),
    ("Ext-Self-Self-Membership", 0x8, "bf9679c0-0de6-11d0-a285-00aa003049e2", True),
    ("Ext-Self-Self-Membership", 0x8, None, False),
])
def test_right_matches_masks_and_object_scope(right, mask, guid, match):
    playbook = load_playbook(SCRIPT)
    helper = __import__(playbook.__module__, fromlist=["matches_expected"]).matches_expected
    ace = {"supported": True, "access": "allowed", "trustee_sid": "S-1-5-7", "inherit_only": False, "object_type": guid, "mask": mask}
    assert helper(ace, "S-1-5-7", right) is match
    ace["access"] = "denied"
    assert not helper(ace, "S-1-5-7", right)


def test_inventory_keeps_all_results_even_with_a_failed_lookup(monkeypatch):
    playbook = load_playbook(SCRIPT)
    module = __import__(playbook.__module__, fromlist=["run"])
    monkeypatch.setattr(module.json, "loads", lambda text: {"source_sha256": "source", "domains": {"north.sevenkingdoms.local": {"dc": "10.60.0.11", "acls": [
        {"name": "grant", "for": "NT AUTHORITY\\ANONYMOUS LOGON", "principal_kind": "well_known", "to": "DC=North,DC=sevenkingdoms,DC=local", "right": "ReadProperty", "inheritance": "All"},
        {"name": "failed", "for": "NT AUTHORITY\\ANONYMOUS LOGON", "principal_kind": "well_known", "to": "DC=North,DC=sevenkingdoms,DC=local", "right": "GenericExecute", "inheritance": "All"},
    ]}}})
    results = []

    def run_module(name, **options):
        assert name == "daclread"
        assert options["principal_sid"] == "S-1-5-7"
        assert "target_dn" in options
        assert options["stop_on_error"] is False
        index = len(results)
        if index == 0:
            data = SimpleNamespace(principal_sid="S-1-5-7", objects=[{"dn": "DC=North,DC=sevenkingdoms,DC=local", "matches": [0], "descriptor": {"aces": [{"supported": True, "access": "allowed", "trustee_sid": "S-1-5-7", "inherit_only": False, "object_type": None, "mask": 0x10, "inherited": False}]}}], missing_targets=[])
            result = ActionResult("ldap", name, "10.60.0.11", ResultStatus.SUCCESS, data)
        else:
            result = ActionResult("ldap", name, "10.60.0.11", ResultStatus.FAILED, SimpleNamespace(message="denied"), error="denied")
        results.append(result)
        return result

    host = SimpleNamespace(target="10.60.0.11", run=SimpleNamespace(results=results), ldap=Mock(return_value=SimpleNamespace(ok=True, module=run_module)), record=lambda result, stop_on_error=False: results.append(result))
    playbook(host)
    summary = results[-1]
    assert summary.status is ResultStatus.FAILED
    assert summary.data.source_count == 2
    assert summary.data.observed_count == 1
    assert summary.data.failed_count == 1
    assert [edge["status"] for edge in summary.data.edges] == ["observed", "failed"]
    assert [edge["dacl_result_index"] for edge in summary.data.edges] == [0, 1]


def test_user_group_expansion_is_reused_and_conditional_dacl_is_ordered(monkeypatch):
    playbook = load_playbook(SCRIPT)
    module = __import__(playbook.__module__, fromlist=["run"])
    monkeypatch.setattr(module.json, "loads", lambda text: {"source_sha256": "source", "domains": {"essos.local": {"dc": "10.60.0.12", "acls": [
        {"name": "allow", "for": "alice", "principal_kind": "user", "to": "first", "right": "GenericAll", "inheritance": "None"},
        {"name": "deny", "for": "alice", "principal_kind": "user", "to": "second", "right": "GenericAll", "inheritance": "None"},
    ]}}})
    results = []
    calls = []

    def run_module(name, **options):
        calls.append(name)
        if name == "token-groups":
            data = SimpleNamespace(groups_returned=True, directory_sids=["S-user", "S-group"])
            action = ActionResult("ldap", name, "10.60.0.12", ResultStatus.SUCCESS, data)
        else:
            first = options["target"] == "first"
            ace = {"index": 0, "supported": True, "access": "allowed" if first else "denied", "trustee_sid": "S-user" if first else "S-group", "inherit_only": False, "flags": 0, "object_type": None, "mask": 0xF01FF, "inherited": False}
            obj = {"dn": options["target"], "sid": "S-target", "matches": [0] if first else [], "descriptor": {"dacl_present": True, "null_dacl": False, "owner_sid": "S-owner", "aces": [ace]}}
            data = SimpleNamespace(principal_sid="S-user", objects=[obj], missing_targets=[])
            action = ActionResult("ldap", name, "10.60.0.12", ResultStatus.SUCCESS if first else ResultStatus.NEGATIVE, data)
        results.append(action)
        return action

    host = SimpleNamespace(target="10.60.0.12", run=SimpleNamespace(results=results), ldap=Mock(return_value=SimpleNamespace(ok=True, module=run_module)), record=lambda result, stop_on_error=False: results.append(result))
    playbook(host)
    summary = results[-1].data
    assert calls == ["daclread", "token-groups", "daclread"]
    assert summary.observed_count == 1
    assert summary.assessed_count == 2
    assert summary.assessed_allowed == 1
    assert summary.assessed_denied == 1
    assert [e["group_result_index"] for e in summary.edges] == [1, 1]
    assert [e["assessments"][0]["dacl"].decision for e in summary.edges] == ["allowed", "denied"]
