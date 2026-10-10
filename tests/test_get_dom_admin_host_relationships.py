"""Offline checks for live host observations in the credential graph."""

from pathlib import Path
from types import SimpleNamespace

from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import load_playbook


SCRIPT = Path(__file__).parents[1] / "examples" / "playbooks" / "getDomAdmin.py"


def playbook_module():
    run = load_playbook(SCRIPT)
    return __import__(run.__module__, fromlist=["KB"])


def test_live_host_relationships_preserve_observer_and_do_not_prove_access():
    module = playbook_module()
    kb = module.KB(SimpleNamespace(), allowed={"10.0.0.20"})
    host = SimpleNamespace(target="10.0.0.20")
    observer = module.Cred("example.test", "analyst", "password")
    sessions = ActionResult("smb", "loggedon_users", host.target, ResultStatus.SUCCESS,
                            SimpleNamespace(users=[SimpleNamespace(domain="EXAMPLE", username="alice",
                                                                   logon_server="DC1"),
                                                   SimpleNamespace(domain="", username="unknown",
                                                                   logon_server="DC1")]))
    groups = ActionResult("smb", "local_groups", host.target, ResultStatus.SUCCESS,
                          SimpleNamespace(groups={"Administrators": 544}, members={
                              "S-1-5-21-1-2-3-1001": "EXAMPLE\\alice", "not-a-sid": "other"},
                                          members_queried=True))
    module.record_live_host_relationships(kb, host, observer, sessions)
    module.record_live_host_relationships(kb, host, observer, sessions)
    module.record_live_host_relationships(kb, host, observer, groups)
    assert len(kb.relationship_edges) == 2
    active, member = kb.relationship_edges
    assert active == {"type": "hasSession", "principal": "EXAMPLE\\alice", "target": host.target,
                      "logon_server": "DC1", "in_scope": True, "source": "smb_wkssvc",
                      "observed_by": "example.test\\analyst", "observed_in_run": True}
    assert member["type"] == "localAdminMember"
    assert member["principal_sid"] == "S-1-5-21-1-2-3-1001"
    assert member["local_group_sid"] == "S-1-5-32-544"
    assert not kb.access_edges
    assert not kb.tier_zero_reached


def test_failed_or_unqueried_host_results_create_no_live_edges():
    module = playbook_module()
    kb = module.KB(SimpleNamespace(), allowed={"10.0.0.20"})
    host = SimpleNamespace(target="10.0.0.20")
    for status, data, action in (
        (ResultStatus.FAILED, SimpleNamespace(users=[SimpleNamespace(domain="EXAMPLE", username="alice")]), "loggedon_users"),
        (ResultStatus.SUCCESS, SimpleNamespace(groups={"Administrators": 544}, members={"S-1-5-1": "alice"},
                                               members_queried=False), "local_groups"),
        (ResultStatus.SUCCESS, SimpleNamespace(groups={"Operators": 544}, members={"S-1-5-1": "alice"},
                                               members_queried=True), "local_groups"),
    ):
        module.record_live_host_relationships(kb, host, None,
                                              ActionResult("smb", action, host.target, status, data))
    assert kb.relationship_edges == []
    outside = ActionResult("smb", "loggedon_users", "10.0.0.99", ResultStatus.SUCCESS,
                           SimpleNamespace(users=[SimpleNamespace(domain="EXAMPLE", username="alice")]))
    module.record_live_host_relationships(kb, SimpleNamespace(target="10.0.0.99"), None, outside)
    assert kb.relationship_edges == []
    module.record_live_host_relationships(kb, host, None, outside)
    assert kb.relationship_edges == []
    wrong_protocol = ActionResult("ldap", "loggedon_users", host.target, ResultStatus.SUCCESS,
                                  SimpleNamespace(users=[SimpleNamespace(domain="EXAMPLE", username="alice")]))
    module.record_live_host_relationships(kb, host, None, wrong_protocol)
    assert kb.relationship_edges == []


def test_smb_enumeration_ingests_typed_session_and_group_results(monkeypatch):
    module = playbook_module()
    kb = module.KB(SimpleNamespace(), default_domain="example.test", allowed={"10.0.0.20"})
    host = SimpleNamespace(target="10.0.0.20")
    observer = module.Cred("example.test", "analyst", "password")
    called = []

    def action(kb, session, name, source, domain, **options):
        called.append(name)
        if name == "loggedon_users":
            return ActionResult("smb", name, host.target, ResultStatus.SUCCESS,
                                SimpleNamespace(users=[SimpleNamespace(domain="EXAMPLE", username="alice",
                                                                       logon_server="DC1")]))
        if name == "local_groups":
            return ActionResult("smb", name, host.target, ResultStatus.SUCCESS,
                                SimpleNamespace(groups={"Administrators": 544},
                                                members={"S-1-5-21-1-2-3-1001": "EXAMPLE\\alice"},
                                                members_queried=True))
        return None

    monkeypatch.setattr(module, "do_action", action)
    monkeypatch.setattr(module, "ENABLE_SPIDER", False)
    module.smb_enumerate(kb, host, observer, object())
    assert "loggedon_users" in called
    assert "local_groups" in called
    assert {edge["type"] for edge in kb.relationship_edges} == {"hasSession", "localAdminMember"}
