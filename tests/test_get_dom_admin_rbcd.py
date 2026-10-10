"""Offline decision-tree checks for the opt-in RBCD transition."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import load_playbook


SCRIPT = Path(__file__).parents[1] / "examples" / "playbooks" / "getDomAdmin.py"


def playbook_module():
    run = load_playbook(SCRIPT)
    return __import__(run.__module__, fromlist=["KB"])


@pytest.mark.parametrize(("write_enabled", "observed_target", "expect_write", "result_modified"), [
    (False, True, False, False), (True, False, False, False),
    (True, True, True, True), (True, True, True, False),
])
def test_rbcd_write_requires_opt_in_allowed_host_and_created_machine(monkeypatch, write_enabled, observed_target, expect_write, result_modified):
    module = playbook_module()
    monkeypatch.setattr(module, "RBCD_TARGET_ACCOUNT", "WEB1$")
    monkeypatch.setattr(module, "ENABLE_RBCD_WRITE", write_enabled)
    monkeypatch.setattr(module, "assess_dacl", lambda descriptor, token_sids, mask, **kwargs: SimpleNamespace(
        decision="allowed" if mask == 0x20 else "denied", reason="offline fixture", ace_indices=[0]))
    kb = module.KB(SimpleNamespace(good=lambda *args, **kwargs: None), default_domain="example.test",
                   allowed={"10.0.0.10", "10.0.0.20"})
    kb.add_host("10.0.0.10", hostname="DC1", dc=True, domain="example.test")
    kb.add_host("10.0.0.20", domain="example.test")
    if observed_target:
        kb.observe_host_identity("10.0.0.20", "WEB1")
    kb.machine_account_actions.append({"account": "NXC1234$", "completed": True, "stored": True,
                                       "credential_queued": True, "credential_ref": {"protocol": "ldap", "id": 7}})
    cred = module.Cred("example.test", "operator", "password")
    dn = "CN=WEB1,CN=Computers,DC=example,DC=test"
    query = ActionResult("ldap", "query", "10.0.0.10", ResultStatus.SUCCESS, SimpleNamespace(
        entries=[{"sAMAccountName": "WEB1$", "distinguishedName": dn,
                  "dNSHostName": "web1.example.test", "objectSid": "S-1-5-21-1-2-3-1001"}],
        distinguished_names=[dn]))
    dacl = ActionResult("ldap", "daclread", "10.0.0.10", ResultStatus.SUCCESS,
                        SimpleNamespace(objects=[{"dn": dn, "descriptor": {"aces": [1]},
                                                  "sid": "S-1-5-21-1-2-3-1001"}]))
    grant = ActionResult("ldap", "rbcd", "10.0.0.10", ResultStatus.SUCCESS, SimpleNamespace(
        action="add", target="WEB1$", target_dn=dn, source="NXC1234$",
        source_sid="S-1-5-21-1-2-3-2000", after_sids=["S-1-5-21-1-2-3-2000"],
        modified=result_modified, completed=True))
    calls = []
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: query)

    def module_call(kb, session, name, step_source, domain, **options):
        calls.append((name, options))
        return SimpleNamespace(results=[grant if name == "rbcd" else dacl])

    monkeypatch.setattr(module, "do_module", module_call)
    module.ldap_rbcd_assessment(kb, SimpleNamespace(target="10.0.0.10"), cred, object(),
                                SimpleNamespace(directory_sids=["S-1-5-21-1-2-3-1000"]),
                                ["S-1-5-11"], "DC=example,DC=test")
    record = kb.acl_assessments[0]
    assert record["decision"] == "candidate"
    assert record["target_host"] == ("10.0.0.20" if observed_target else None)
    assert [name for name, _ in calls].count("rbcd") == int(expect_write)
    assert (record["next_action"]["completed"] if record["next_action"] else False) is (expect_write and result_modified)
    assert kb.rbcd_grant_completed is (expect_write and result_modified)
    if expect_write:
        assert calls[-1][1] == {"target": "WEB1$", "target_dn": dn,
                                "source": "NXC1234$", "action": "add"}
        assert not kb.tier_zero_reached
    if kb.rbcd_grant_completed:
        module.execute_rbcd_control(kb, SimpleNamespace(target="10.0.0.10"), cred, object(),
                                    {**record, "target_dn": "CN=WEB2,CN=Computers,DC=example,DC=test"})
        assert [name for name, _ in calls].count("rbcd") == 1


def test_rbcd_target_match_rejects_ambiguous_or_foreign_hosts():
    module = playbook_module()
    kb = module.KB(SimpleNamespace(), default_domain="example.test", allowed={"10.0.0.20", "10.0.0.21"})
    kb.add_host("10.0.0.20", hostname="WEB1", domain="example.test")
    kb.add_host("10.0.0.21", domain="example.test")
    assert module.match_rbcd_target(kb, "WEB1$", "web1.example.test") is None
    kb.observe_host_identity("10.0.0.20", "WEB1")
    kb.observe_host_identity("10.0.0.21", "WEB1")
    assert module.match_rbcd_target(kb, "WEB1$", "web1.example.test") is None
    kb.observed_hostnames["10.0.0.21"].clear()
    assert module.match_rbcd_target(kb, "WEB1$", "web1.foreign.test") is None
    assert module.match_rbcd_target(kb, "WEB1$", "web1.example.test") == "10.0.0.20"


def test_rbcd_default_targets_only_observed_allowed_same_domain_hosts(monkeypatch):
    module = playbook_module()
    monkeypatch.setattr(module, "RBCD_TARGET_ACCOUNT", "")
    kb = module.KB(SimpleNamespace(), default_domain="example.test",
                   allowed={"10.0.0.20", "10.0.0.21", "10.0.0.22"})
    kb.add_host("10.0.0.20", domain="example.test")
    kb.add_host("10.0.0.21", domain="foreign.test")
    kb.observe_host_identity("10.0.0.20", "WEB1")
    kb.observe_host_identity("10.0.0.20", "web1.example.test")
    kb.observe_host_identity("10.0.0.23", "IGNORED")
    kb.observe_host_identity("10.0.0.21", "WEB2")
    kb.observe_host_identity("10.0.0.22", "10.0.0.22")
    assert module.rbcd_target_accounts(kb) == ["web1$"]
