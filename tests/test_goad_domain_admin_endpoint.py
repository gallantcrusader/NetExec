"""Tier-zero host checks require both computed membership and SMB admin evidence."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nxc.playbooks.results import ActionResult, CredentialRef, ResultStatus
from nxc.playbooks.runner import load_playbook


SCRIPT = Path(__file__).parents[1] / "examples" / "playbooks" / "goad_domain_admin_endpoint.py"


@pytest.mark.parametrize(("computed_sid", "smb_admin", "expected_reached", "smb_calls"), [
    (True, True, True, 1),
    (True, False, False, 1),
    (False, True, False, 0),
])
def test_endpoint_requires_verified_membership_and_smb_admin(tmp_path, monkeypatch, computed_sid, smb_admin, expected_reached, smb_calls):
    run = load_playbook(SCRIPT)
    module = __import__(run.__module__, fromlist=["NXC_PATH"])
    monkeypatch.setattr(module, "NXC_PATH", tmp_path)
    graph_dir = tmp_path / "playbooks"
    graph_dir.mkdir()
    graph = {"unresolved": [], "verified_count": 1, "source_count": 1, "domain_admin_membership_paths": [{"user": "alice", "user_domain": "essos.local", "target_domain": "essos.local", "user_sid": "S-user", "target_sid": "S-da", "edge_indices": [0]}]}
    (graph_dir / "goad-membership-graph.json").write_text(json.dumps(graph), encoding="utf-8")
    results = []
    reference = CredentialRef("ldap", 7)
    connect_data = SimpleNamespace(authenticated=True, credential=reference)
    token_data = SimpleNamespace(groups_returned=True, principal_sid="S-user", directory_sids=["S-da"] if computed_sid else [])
    smb_data = SimpleNamespace(authenticated=True, admin_privileges=smb_admin, admin_check_error=None)
    called = []

    def ldap_module(name, **options):
        assert name == "token-groups"
        assert options["principal"] == "alice"
        result = ActionResult("ldap", name, "10.60.0.12", ResultStatus.SUCCESS, token_data)
        results.append(result)
        return result

    def ldap():
        result = ActionResult("ldap", "connect", "10.60.0.12", ResultStatus.SUCCESS, connect_data)
        results.append(result)
        return SimpleNamespace(ok=True, result=result, connection=SimpleNamespace(username="alice"), module=ldap_module)

    def smb(**options):
        called.append(options)
        result = ActionResult("smb", "connect", "10.60.0.12", ResultStatus.SUCCESS, smb_data)
        results.append(result)
        return SimpleNamespace(ok=True, result=result)

    host = SimpleNamespace(target="10.60.0.12", run=SimpleNamespace(results=results), ldap=ldap, smb=smb, record=lambda result, stop_on_error=False: results.append(result))
    run(host)
    summary = results[-1]
    assert summary.action == "goad_domain_admin_endpoint"
    assert summary.data.reached_tier_zero_host is expected_reached
    assert summary.status is (ResultStatus.SUCCESS if expected_reached else ResultStatus.NEGATIVE)
    assert len(called) == smb_calls
    if called:
        assert called[0]["credential"] == reference


def test_failed_directory_login_still_records_a_typed_path_result(tmp_path, monkeypatch):
    run = load_playbook(SCRIPT)
    module = __import__(run.__module__, fromlist=["NXC_PATH"])
    monkeypatch.setattr(module, "NXC_PATH", tmp_path)
    graph_dir = tmp_path / "playbooks"
    graph_dir.mkdir()
    (graph_dir / "goad-membership-graph.json").write_text(json.dumps({"unresolved": [], "verified_count": 1, "source_count": 1}), encoding="utf-8")
    results = []

    def ldap():
        result = ActionResult("ldap", "connect", "10.60.0.10", ResultStatus.NEGATIVE, SimpleNamespace(authenticated=False))
        results.append(result)
        return SimpleNamespace(ok=False, result=result, connection=SimpleNamespace(username="robert.baratheon"))

    host = SimpleNamespace(target="10.60.0.10", run=SimpleNamespace(results=results), ldap=ldap, record=lambda result, stop_on_error=False: results.append(result))
    run(host)
    summary = results[-1]
    assert summary.action == "goad_domain_admin_endpoint"
    assert summary.status is ResultStatus.NEGATIVE
    assert summary.data.user == "robert.baratheon"
    assert summary.data.reason == "Directory login was not established"
    assert summary.data.evidence_indices == [0]


def test_admin_check_timeout_is_failure_not_denial(tmp_path, monkeypatch):
    run = load_playbook(SCRIPT)
    module = __import__(run.__module__, fromlist=["NXC_PATH"])
    monkeypatch.setattr(module, "NXC_PATH", tmp_path)
    graph_dir = tmp_path / "playbooks"
    graph_dir.mkdir()
    (graph_dir / "goad-membership-graph.json").write_text(json.dumps({"unresolved": [], "verified_count": 1, "source_count": 1, "domain_admin_membership_paths": [{"user": "alice", "user_domain": "essos.local", "target_domain": "essos.local", "user_sid": "S-user", "target_sid": "S-da"}]}), encoding="utf-8")
    results = []

    def ldap_module(name, **options):
        result = ActionResult("ldap", name, "10.60.0.12", ResultStatus.SUCCESS, SimpleNamespace(groups_returned=True, principal_sid="S-user", directory_sids=["S-da"]))
        results.append(result)
        return result

    def ldap():
        result = ActionResult("ldap", "connect", "10.60.0.12", ResultStatus.SUCCESS, SimpleNamespace(authenticated=True, credential=CredentialRef("ldap", 7)))
        results.append(result)
        return SimpleNamespace(ok=True, result=result, connection=SimpleNamespace(username="alice"), module=ldap_module)

    def smb(**options):
        result = ActionResult("smb", "connect", "10.60.0.12", ResultStatus.SUCCESS, SimpleNamespace(authenticated=True, admin_privileges=None, admin_check_error="timed out"))
        results.append(result)
        return SimpleNamespace(ok=True, result=result)

    host = SimpleNamespace(target="10.60.0.12", run=SimpleNamespace(results=results), ldap=ldap, smb=smb, record=lambda result, stop_on_error=False: results.append(result))
    run(host)
    summary = results[-1]
    assert summary.status is ResultStatus.FAILED
    assert summary.error == "timed out"
    assert summary.data.admin_check_error == "timed out"
    assert summary.data.reached_tier_zero_host is False
