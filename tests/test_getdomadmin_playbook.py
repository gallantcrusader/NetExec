"""Offline checks for the getDomAdmin playbook's traversal and evidence boundary."""

import importlib.util
import sqlite3
import sys
import threading
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


@pytest.fixture
def playbook(tmp_path, monkeypatch):
    config = ModuleType("nxc.config")
    config.nxc_workspace = "lab"
    paths = ModuleType("nxc.paths")
    paths.NXC_PATH = str(tmp_path / "output")
    paths.WORKSPACE_DIR = str(tmp_path)
    monkeypatch.setitem(sys.modules, "nxc.config", config)
    monkeypatch.setitem(sys.modules, "nxc.paths", paths)

    name = "getdomadmin_test_module"
    file = Path(__file__).resolve().parents[1] / "examples" / "playbooks" / "getDomAdmin.py"
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


class QuietLog:
    base = "/tmp/offline-getdomadmin"

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def test_anonymous_state_queues_once_and_rejects_unapproved_target(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10"})

    kb.enqueue(None, "192.0.2.10")
    kb.enqueue(None, "192.0.2.10")

    assert kb.worklist == [(None, "192.0.2.10")]
    with pytest.raises(ValueError, match="outside"):
        kb.enqueue(None, "192.0.2.11")


@pytest.mark.parametrize("endpoint", ["dns_server", "kdc_host"])
def test_auxiliary_auth_endpoints_must_be_explicitly_allowed(playbook, endpoint):
    kb = playbook.KB(QuietLog(), **{endpoint: "192.0.2.53"})
    host = SimpleNamespace(target="192.0.2.10", workflow=SimpleNamespace(allowed_targets=["192.0.2.10"]))

    with pytest.raises(ValueError, match="outside the explicit target list"):
        playbook.discover_hosts(kb, host)


@pytest.mark.parametrize("endpoint", ["dns_server", "kdc_host"])
def test_auxiliary_auth_endpoints_must_be_literal_ips(playbook, endpoint):
    host = SimpleNamespace(
        target="192.0.2.10",
        workflow=SimpleNamespace(allowed_targets=["192.0.2.10", "dns.example.test"]),
        connection_defaults={},
    )
    settings = {"dns_server": "192.0.2.10", "kdc_host": ""}
    settings[endpoint] = "dns.example.test"
    kb = playbook.KB(QuietLog(), **settings)

    with pytest.raises(ValueError, match="must be a literal IP address"):
        playbook.discover_hosts(kb, host)


def test_kerberos_auth_requires_an_explicit_allowed_kdc(playbook):
    host = SimpleNamespace(
        target="192.0.2.10",
        workflow=SimpleNamespace(allowed_targets=["192.0.2.10", "192.0.2.11"]),
        connection_defaults={"kerberos": True},
    )
    kb = playbook.KB(QuietLog())

    with pytest.raises(ValueError, match="Kerberos authentication requires --kdcHost"):
        playbook.discover_hosts(kb, host)

    kb = playbook.KB(QuietLog(), kdc_host="192.0.2.11", dns_server="192.0.2.11")
    playbook.discover_hosts(kb, host)
    assert kb.kdc_host in kb.allowed


def test_discover_hosts_requires_an_allowed_dns_server(playbook):
    host = SimpleNamespace(
        target="192.0.2.10",
        workflow=SimpleNamespace(allowed_targets=["192.0.2.10"]),
        connection_defaults={},
    )
    with pytest.raises(ValueError, match="--dns-server must exactly match an allowed target"):
        playbook.discover_hosts(playbook.KB(QuietLog()), host)


def test_workspace_credentials_detect_new_and_updated_rows(playbook, tmp_path):
    db_file = tmp_path / "lab" / "smb.db"
    db_file.parent.mkdir()
    with sqlite3.connect(db_file) as conn:
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, domain TEXT, username TEXT, credtype TEXT, password TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'example.test', 'krbtgt', 'hash', ':" + "a" * 32 + "')")

    kb = playbook.KB(QuietLog(), default_domain="example.test", allowed={"192.0.2.10"})
    playbook.snapshot_workspace_credentials(kb)
    assert kb.baseline_credentials["smb"][1] == ("example.test", "krbtgt", "hash", ":" + "a" * 32)

    class FakeDB:
        def get_credentials(self):
            return [SimpleNamespace(_mapping=row) for row in [
                {"id": 1, "domain": "example.test", "username": "krbtgt", "password": ":" + "b" * 32, "credtype": "hash"},
                {"id": 2, "domain": "example.test", "username": "student", "password": "sample", "credtype": "plaintext"},
            ]]

        def get_hosts(self):
            return []

        def get_admin_relations(self):
            return []

        def get_loggedin_relations(self):
            return []

    playbook.sync_db(kb, SimpleNamespace(db=FakeDB()), "smb", source="ntds-db")

    assert not kb.da_reached
    assert {cred.username for cred in kb.creds.values()} == {"krbtgt", "student"}
    assert len(kb.worklist) == 2


def test_seed_or_local_krbtgt_hash_is_not_domain_compromise(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10"})

    kb.add_cred(playbook.Cred("example.test", "krbtgt", ":" + "a" * 32, "hash", source="seed"))
    kb.add_cred(playbook.Cred("", "krbtgt", ":" + "b" * 32, "hash", local=True, source="ntds"))
    kb.add_cred(playbook.Cred("example.test", "krbtgt", ":" + "c" * 32, "hash", source="ntds-db"))

    assert not kb.da_reached


def test_direct_ntds_output_can_prove_domain_compromise(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10"})
    nt_hash = "a" * 32
    output = SimpleNamespace(events=[SimpleNamespace(message=f"EXAMPLE\\krbtgt:502:{'0' * 32}:{nt_hash}:::")])

    playbook.harvest_events(kb, output, "ntds", "example.test")

    assert kb.da_reached


def test_pre2k_is_opt_in_and_never_uses_all_accounts(playbook, monkeypatch):
    calls = []
    monkeypatch.setattr(playbook, "do_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(playbook, "do_module", lambda *args, **kwargs: calls.append((args[2], kwargs)))
    kb = playbook.KB(QuietLog(), default_domain="example.test", kdc_host="192.0.2.10", allowed={"192.0.2.10"})

    monkeypatch.setattr(playbook, "ENABLE_KERBEROS_PROBES", False)
    playbook.ldap_secrets(kb, None, None, object())
    assert not any(name == "pre2k" for name, _ in calls)

    calls.clear()
    monkeypatch.setattr(playbook, "ENABLE_KERBEROS_PROBES", True)
    playbook.ldap_secrets(kb, None, None, object())
    assert ("pre2k", {}) in calls


def test_laps_is_opt_in_and_requires_an_allowed_dns_server(playbook, monkeypatch):
    calls = []
    monkeypatch.setattr(playbook, "do_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(playbook, "do_module", lambda *args, **kwargs: calls.append((args[2], kwargs)))
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10"})

    monkeypatch.setattr(playbook, "ENABLE_LAPS", False)
    playbook.ldap_secrets(kb, None, None, object())
    assert not any(name == "laps" for name, _ in calls)

    monkeypatch.setattr(playbook, "ENABLE_LAPS", True)
    playbook.ldap_secrets(kb, None, None, object())
    assert not any(name == "laps" for name, _ in calls)

    kb.dns_server = "192.0.2.10"
    playbook.ldap_secrets(kb, None, None, object())
    assert ("laps", {}) in calls


def test_laps_secret_is_local_to_exact_host_and_smb_only(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10", "192.0.2.11"})
    kb.observe_host_identity("192.0.2.11", "win1.example.test")
    record = SimpleNamespace(
        computer="WIN1$",
        dns_hostname="win1.example.test",
        username="Administrator",
        password="sample-local-secret",
    )
    result = SimpleNamespace(results=[SimpleNamespace(data=SimpleNamespace(computers=[record]))])

    playbook.harvest_laps_result(kb, result, "example.test")

    [cred] = kb.creds.values()
    assert cred.local
    assert cred.target_scope == "192.0.2.11"
    assert cred.protocols == ("smb",)
    assert kb.worklist == [(cred, "192.0.2.11")]

    class FakeDB:
        def get_credentials(self):
            return [SimpleNamespace(_mapping={
                "id": 1, "domain": "EXAMPLE", "username": "Administrator",
                "password": "sample-local-secret", "credtype": "plaintext",
                "pillaged_from_hostid": None,
            })]

        def get_hosts(self):
            return []

        def get_admin_relations(self):
            return []

        def get_loggedin_relations(self):
            return []

    kb.baseline_credentials["smb"] = {}
    session = SimpleNamespace(db=FakeDB(), credential=SimpleNamespace(protocol="smb", id=1))
    playbook.sync_db(kb, session, "smb", target="192.0.2.11")
    assert len(kb.creds) == 1
    assert kb.worklist == [(cred, "192.0.2.11")]


def test_laps_echo_suppression_is_exact_and_source_limited(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10", "192.0.2.11"})
    scoped = playbook.Cred("", "Administrator", "CaseSensitive", "plaintext", local=True,
                           source="laps", target_scope="192.0.2.10", protocols=("smb",))
    kb.add_cred(scoped)

    row = {"id": 21}
    session = SimpleNamespace(credential=SimpleNamespace(protocol="smb", id=21))
    assert playbook.is_scoped_smb_echo(kb, session, "smb", "192.0.2.10", None, row,
                                       "administrator", "CaseSensitive", "plaintext")
    assert not playbook.is_scoped_smb_echo(kb, session, "smb", "192.0.2.11", None, row,
                                           "administrator", "CaseSensitive", "plaintext")
    assert not playbook.is_scoped_smb_echo(kb, session, "smb", "192.0.2.10", "ntds-db", row,
                                           "administrator", "CaseSensitive", "plaintext")
    assert not playbook.is_scoped_smb_echo(kb, session, "smb", "192.0.2.10", None, row,
                                           "administrator", "casesensitive", "plaintext")
    assert not playbook.is_scoped_smb_echo(kb, session, "smb", "192.0.2.10", None, {"id": 22},
                                           "administrator", "CaseSensitive", "plaintext")


def test_independent_credential_with_case_distinct_secret_is_kept(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10"})
    kb.add_cred(playbook.Cred("", "Administrator", "CaseSensitive", "plaintext", local=True,
                              source="laps", target_scope="192.0.2.10", protocols=("smb",)))
    output = SimpleNamespace(events=[SimpleNamespace(
        message="Username:Administrator Password:casesensitive"
    )])

    playbook.harvest_events(kb, output, "loot:gpp", "example.test")

    assert len(kb.creds) == 2
    assert any(c.source.startswith("loot:gpp:") and c.secret == "casesensitive" for c in kb.creds.values())


def test_domain_credentials_with_case_distinct_secrets_are_distinct(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10"})

    kb.add_cred(playbook.Cred("example.test", "administrator", "CaseSensitive", source="seed"))
    kb.add_cred(playbook.Cred("EXAMPLE.TEST", "Administrator", "casesensitive", source="ntds"))

    assert len(kb.creds) == 2
    assert {cred.secret for cred in kb.creds.values()} == {"CaseSensitive", "casesensitive"}

    assert playbook.Cred("example.test", "user", ":" + "ab" * 16, "hash").key() == playbook.Cred(
        "example.test", "user", ":" + "AB" * 16, "hash"
    ).key()


def test_domain_secret_reads_are_opt_in(playbook, monkeypatch):
    actions = []
    modules = []
    monkeypatch.setattr(playbook, "do_action", lambda *args, **kwargs: actions.append(args[2]))
    monkeypatch.setattr(playbook, "do_module", lambda *args, **kwargs: modules.append(args[2]))
    kb = playbook.KB(QuietLog(), default_domain="example.test", allowed={"192.0.2.10"})

    monkeypatch.setattr(playbook, "ENABLE_DOMAIN_SECRETS", False)
    playbook.ldap_enumerate(kb, None, None, object())
    playbook.ldap_secrets(kb, None, None, object())
    playbook.smb_dcsync(kb, SimpleNamespace(target="192.0.2.10"), None, SimpleNamespace(db=None))
    assert "gmsa" not in actions
    assert "user-desc" not in modules
    assert "get-info-users" not in modules
    assert "get-userPassword" not in modules
    assert "get-unixUserPassword" not in modules
    assert "daclread" not in modules
    assert "shadow-creds" not in modules
    assert "ntds" not in actions

    actions.clear()
    modules.clear()
    monkeypatch.setattr(playbook, "ENABLE_DOMAIN_SECRETS", True)
    playbook.ldap_enumerate(kb, None, None, object())
    playbook.ldap_secrets(kb, None, None, object())
    playbook.smb_dcsync(kb, SimpleNamespace(target="192.0.2.10"), None, SimpleNamespace(db=None))
    assert "gmsa" in actions
    assert "user-desc" in modules
    assert "get-info-users" in modules
    assert "get-userPassword" in modules
    assert "get-unixUserPassword" in modules
    assert "daclread" not in modules
    assert "shadow-creds" not in modules
    assert "ntds" in actions


def test_dc_classification_uses_live_smb_connection_metadata(playbook):
    target = "192.0.2.10"
    calls = []
    connection = SimpleNamespace(isdc=True, hostname="dc.example.test")
    session = SimpleNamespace(
        connection=connection,
        result=SimpleNamespace(data=SimpleNamespace(connected=True)),
        ok=True,
        authenticated=False,
        admin=None,
    )
    host = SimpleNamespace(target=target, smb=lambda **kwargs: calls.append(kwargs) or session)
    kb = playbook.KB(QuietLog(), allowed={target})

    assert playbook.open_session(kb, host, "smb", None) is session
    assert calls == [{"anonymous": True, "no_smbv1": True}]
    assert kb.hosts[target]["dc"] is True


def test_sccm_resolution_requires_opt_in_and_allowed_dns(playbook, monkeypatch):
    calls = []
    monkeypatch.setattr(playbook, "do_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(playbook, "do_module", lambda *args, **kwargs: calls.append(args[2]))
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10", "192.0.2.53"})

    monkeypatch.setattr(playbook, "ENABLE_SCCM", False)
    playbook.ldap_secrets(kb, None, None, object())
    assert "sccm" not in calls

    monkeypatch.setattr(playbook, "ENABLE_SCCM", True)
    playbook.ldap_secrets(kb, None, None, object())
    assert "sccm" not in calls

    kb.dns_server = "192.0.2.53"
    playbook.ldap_secrets(kb, None, None, object())
    assert calls.count("sccm") == 1


def test_laps_mapping_ignores_stale_workspace_hostnames(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.11"})
    kb.add_host("192.0.2.11", hostname="old-computer.example.test")
    record = SimpleNamespace(
        computer="OLD-COMPUTER$", dns_hostname="old-computer.example.test",
        username="Administrator", password="sample-local-secret",
    )

    assert playbook.match_laps_target(kb, record) is None


def test_laps_log_text_is_not_parsed_as_a_domain_credential(playbook):
    kb = playbook.KB(QuietLog(), allowed={"192.0.2.10"})
    output = SimpleNamespace(events=[SimpleNamespace(message="Computer:WIN1 User:Administrator Password:sample-secret")])

    playbook.harvest_events(kb, output, "ldap-secrets:laps", "example.test")

    assert not kb.creds


def test_soft_timeout_waits_for_worker_before_returning(playbook):
    finished = threading.Event()

    def operation():
        time.sleep(0.02)
        finished.set()

    _, timed_out = playbook.run_bounded(operation, 0.001, QuietLog(), "test operation")

    assert timed_out
    assert finished.is_set()


def test_step_budget_stops_action_and_module_dispatch(playbook, monkeypatch):
    monkeypatch.setattr(playbook, "MAX_STEPS", 2)
    kb = playbook.KB(QuietLog(), steps=2)

    class NoDispatch:
        def __getattr__(self, name):
            raise AssertionError(f"unexpected action: {name}")

        def module(self, name, **kwargs):
            raise AssertionError(f"unexpected module: {name}")

    assert playbook.do_action(kb, NoDispatch(), "shares", "test", "example.test") is None
    assert playbook.do_module(kb, NoDispatch(), "laps", "test", "example.test") is None
    assert kb.steps == 2


@pytest.mark.parametrize("seed", [False, True])
def test_run_does_not_report_seed_or_anonymous_access_as_domain_compromise(playbook, monkeypatch, seed):
    class FakeHost:
        target = "192.0.2.10"
        connection_defaults = {"domain": "example.test", "dns_server": target}
        workflow = SimpleNamespace(allowed_targets=[target])

        def __init__(self):
            self.calls = 0
            self.verdict = None

        def defaults(self, **kwargs):
            pass

        def smb(self, **kwargs):
            self.calls += 1
            if seed and self.calls == 1:
                return SimpleNamespace(ok=True, db=None, connection=SimpleNamespace(username="student", domain="example.test", password="sample", nthash=""))
            return SimpleNamespace(ok=False, db=None, connection=None, result=None)

        def ldap(self, **kwargs):
            return SimpleNamespace(ok=False, db=None, connection=None, result=None)

        def finding(self, name, **kwargs):
            self.verdict = kwargs
            return kwargs

    monkeypatch.setattr(playbook, "preflight_tools", lambda kb: None)
    monkeypatch.setattr(playbook, "Log", lambda target: QuietLog())
    monkeypatch.setattr(playbook, "MAX_STEPS", 1 if seed else 20)
    result = playbook.run(FakeHost())

    assert result["ok"] is False
    assert result["data"].da_reached is False
    assert result["data"].termination == ("budget_exhausted" if seed else "saturated")


def test_mid_batch_budget_limit_preserves_unprocessed_states(playbook, monkeypatch):
    class FakeHost:
        target = "192.0.2.10"
        connection_defaults = {"dns_server": target}
        workflow = SimpleNamespace(allowed_targets=[target, "192.0.2.11"])

        def __init__(self):
            self.verdict = None

        def defaults(self, **kwargs):
            pass

        def finding(self, name, **kwargs):
            self.verdict = kwargs
            return kwargs

    monkeypatch.setattr(playbook, "preflight_tools", lambda kb: None)
    monkeypatch.setattr(playbook, "snapshot_workspace_credentials", lambda kb: None)
    monkeypatch.setattr(playbook, "seed_credentials", lambda kb, root: None)
    monkeypatch.setattr(playbook, "Log", lambda target: QuietLog())
    monkeypatch.setattr(playbook, "MAX_STEPS", 1)
    monkeypatch.setattr(playbook, "process_state", lambda kb, root, cred, target: setattr(kb, "steps", 1))

    result = playbook.run(FakeHost())

    assert result["data"].termination == "budget_exhausted"
    assert result["data"].pending_states == 1


def test_budget_hit_inside_last_state_is_not_reported_as_saturation(playbook, monkeypatch):
    class FakeHost:
        target = "192.0.2.10"
        connection_defaults = {"dns_server": target}
        workflow = SimpleNamespace(allowed_targets=[target])

        def defaults(self, **kwargs):
            pass

        def smb(self, **kwargs):
            return SimpleNamespace(ok=False, db=None, result=None)

        def finding(self, name, **kwargs):
            return kwargs

    monkeypatch.setattr(playbook, "preflight_tools", lambda kb: None)
    monkeypatch.setattr(playbook, "snapshot_workspace_credentials", lambda kb: None)
    monkeypatch.setattr(playbook, "seed_credentials", lambda kb, root: None)
    monkeypatch.setattr(playbook, "Log", lambda target: QuietLog())
    monkeypatch.setattr(playbook, "MAX_STEPS", 1)

    result = playbook.run(FakeHost())

    assert result["data"].termination == "budget_exhausted"
    assert result["data"].pending_states == 0


@pytest.mark.parametrize(
    ("find_status", "trusted_ok", "delegations", "expected_findings"),
    [
        ("negative", False, [], []),
        ("failed", True, [], ["delegation (find_delegation) incomplete on 192.0.2.10"]),
        (
            "success",
            True,
            [{
                "account_name": "svc_buildlink$",
                "delegation_type": "Resource-Based Constrained",
                "delegation_rights_to": "CPTS-DC02$",
            }],
            ["RBCD: svc_buildlink$ is allowed on CPTS-DC02$"],
        ),
    ],
)
def test_ldap_delegation_reports_structured_find_results(
    playbook, monkeypatch, find_status, trusted_ok, delegations, expected_findings
):
    kb = playbook.KB(QuietLog(), default_domain="example.test")
    host = SimpleNamespace(target="192.0.2.10")

    def action(_kb, _session, name, *_args, **_kwargs):
        if name == "find_delegation":
            return SimpleNamespace(
                ok=find_status == "success", status=find_status, data=SimpleNamespace(delegations=delegations)
            )
        return SimpleNamespace(ok=trusted_ok)

    monkeypatch.setattr(playbook, "do_action", action)

    playbook.ldap_delegation(kb, host, None, object())

    assert kb.findings == expected_findings


def test_ldap_delegation_retains_partial_structured_results(playbook, monkeypatch):
    kb = playbook.KB(QuietLog(), default_domain="example.test")
    host = SimpleNamespace(target="192.0.2.10")
    delegation = {
        "account_name": "svc_buildlink$",
        "delegation_type": "Resource-Based Constrained",
        "delegation_rights_to": "CPTS-DC02$",
    }

    def action(_kb, _session, name, *_args, **_kwargs):
        if name == "find_delegation":
            return SimpleNamespace(
                ok=False, error="one principal lookup failed", data=SimpleNamespace(delegations=[delegation])
            )
        return SimpleNamespace(ok=True)

    monkeypatch.setattr(playbook, "do_action", action)

    playbook.ldap_delegation(kb, host, None, object())

    assert kb.findings == ["partial RBCD: svc_buildlink$ is allowed on CPTS-DC02$"]
