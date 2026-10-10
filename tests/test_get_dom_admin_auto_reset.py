"""Automatic privileged-user reset discovery and bounded execution."""

from pathlib import Path
from types import SimpleNamespace

from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import load_playbook


SCRIPT = Path(__file__).parents[1] / "examples" / "playbooks" / "getDomAdmin.py"
ROOT_DN = "DC=example,DC=test"
GROUP_DN = "CN=Domain Admins,CN=Users,DC=example,DC=test"
SID = "S-1-5-21-1-2-3-1000"


def playbook_module():
    run = load_playbook(SCRIPT)
    return __import__(run.__module__, fromlist=["KB"])


def fixture():
    module = playbook_module()
    log = SimpleNamespace(good=lambda *args, **kwargs: None)
    kb = module.KB(log, default_domain="example.test", allowed={"10.0.0.10"})
    kb.add_host("10.0.0.10", dc=True, domain="example.test")
    actor = module.Cred("example.test", "analyst", "password")
    kb.add_cred(actor)
    kb.acl_assessments.append({"target_type": "group", "target_sid": "S-1-5-21-1-2-3-512",
                               "target_dn": GROUP_DN, "principal": actor.principal(),
                               "source_host": "10.0.0.10"})
    token = SimpleNamespace(principal_sid=SID, directory_sids=[SID])
    host = SimpleNamespace(target="10.0.0.10")
    entries = [{"distinguishedName": f"CN={name},CN=Users,{ROOT_DN}",
                "sAMAccountName": name, "objectSid": f"S-1-5-21-1-2-3-{rid}",
                "objectClass": ["top", "user"]} for name, rid in (("da.z", 1101), ("da.a", 1100))]
    query = ActionResult("ldap", "query", host.target, ResultStatus.SUCCESS,
                         SimpleNamespace(entries=entries, distinguished_names=[]))
    return module, kb, actor, token, host, query


def dacl_for(dn):
    descriptor = {"dacl_present": True, "null_dacl": False, "owner_sid": "other", "aces": [
        {"index": 0, "supported": True, "flags": 0, "access": "allowed", "trustee_sid": SID,
         "mask": 0x100, "object_type": "00299570-246d-11d0-a768-00aa006e0529"},
    ]}
    return ActionResult("ldap", "daclread", "10.0.0.10", ResultStatus.SUCCESS,
                        SimpleNamespace(objects=[{"dn": dn, "descriptor": descriptor, "error": None}]))


def test_auto_reset_requires_an_observed_domain_admin_group(monkeypatch):
    module, kb, actor, token, host, query = fixture()
    kb.acl_assessments.clear()
    monkeypatch.setattr(module, "RESET_TARGET_USER", "auto")
    called = []
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: called.append(kwargs))
    module.ldap_user_reset_assessment(kb, host, actor, object(), token, ["S-1-5-11"], ROOT_DN)
    assert called == []


def test_auto_reset_queries_nested_membership_and_caps_acl_reads(monkeypatch):
    module, kb, actor, token, host, query = fixture()
    query.data.entries.append({"distinguishedName": f"CN=analyst,CN=Users,{ROOT_DN}",
                               "sAMAccountName": "analyst", "objectClass": ["user"]})
    query.data.entries.append({"distinguishedName": "CN=foreign,DC=foreign,DC=test",
                               "sAMAccountName": "aa.foreign", "objectClass": ["user"]})
    monkeypatch.setattr(module, "RESET_TARGET_USER", "auto")
    monkeypatch.setattr(module, "MAX_AUTO_RESET_TARGETS", 1)
    monkeypatch.setattr(module, "ENABLE_PASSWORD_RESET", False)
    searches = []
    dacl_names = []

    def action(*args, **kwargs):
        searches.append(kwargs["query"][0])
        return query

    def loaded(*args, **kwargs):
        dacl_names.append(kwargs["target_dn"])
        return SimpleNamespace(results=[dacl_for(kwargs["target_dn"])])

    monkeypatch.setattr(module, "do_action", action)
    monkeypatch.setattr(module, "do_module", loaded)
    module.ldap_user_reset_assessment(kb, host, actor, object(), token, ["S-1-5-11"], ROOT_DN)
    assert len(searches) == 1
    assert f"memberOf:1.2.840.113556.1.4.1941:={GROUP_DN}" in searches[0]
    assert dacl_names == [f"CN=da.a,CN=Users,{ROOT_DN}"]
    assert kb.acl_assessments[-1]["decision"] == "candidate"
    assert kb.acl_assessments[-1]["auto_selected"]
    assert kb.acl_assessments[-1]["next_action"]["executed"] is False
    assert any("capped at 1 of 2" in finding for finding in kb.findings)


def test_auto_reset_opt_in_attempts_only_one_candidate(monkeypatch):
    module, kb, actor, token, host, query = fixture()
    monkeypatch.setattr(module, "RESET_TARGET_USER", "auto")
    monkeypatch.setattr(module, "MAX_AUTO_RESET_TARGETS", 2)
    monkeypatch.setattr(module, "ENABLE_PASSWORD_RESET", True)
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda length: "replacement")
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: query)
    monkeypatch.setattr(module, "open_session", lambda *args, **kwargs: SimpleNamespace(
        authenticated=True, connection=SimpleNamespace(domain="example.test")))
    resets = []

    def loaded(kb, session, name, source, domain, **options):
        if name == "daclread":
            return SimpleNamespace(results=[dacl_for(options["target_dn"])])
        resets.append(options["user"])
        data = SimpleNamespace(completed=True, stored=True, username=options["user"],
                               domain="example.test", credential_kind="plaintext",
                               new_secret="replacement", credential_id=42)
        return SimpleNamespace(results=[ActionResult("smb", "change-password", host.target,
                                                     ResultStatus.SUCCESS, data)])

    monkeypatch.setattr(module, "do_module", loaded)
    module.ldap_user_reset_assessment(kb, host, actor, object(), token, ["S-1-5-11"], ROOT_DN)
    assert resets == ["da.a"]
    assert kb.password_reset_attempted
    assert {record["target_name"] for record in kb.acl_assessments if record.get("target_type") == "user"} == {"da.a", "da.z"}
    assert any(cred.username == "da.a" and cred.db_ref == ("smb", 42) for cred in kb.creds.values())
