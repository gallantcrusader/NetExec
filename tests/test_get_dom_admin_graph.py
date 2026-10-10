"""Local graph and proof checks for the getDomAdmin playbook."""

from pathlib import Path
from types import SimpleNamespace

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import load_playbook


SCRIPT = Path(__file__).parents[1] / "examples" / "playbooks" / "getDomAdmin.py"


class Log:
    def __init__(self):
        self.messages = []
        self.base = "/tmp/get-dom-admin-test"

    def good(self, message, **fields):
        self.messages.append(message)

    def crit(self, message, **fields):
        self.messages.append(message)

    def step(self, message, **fields):
        self.messages.append(message)

    def info(self, message, **fields):
        self.messages.append(message)

    def warn(self, message, **fields):
        self.messages.append(message)

    def close(self):
        pass


def playbook_module():
    run = load_playbook(SCRIPT)
    return __import__(run.__module__, fromlist=["KB"])


def test_host_roles_and_first_discovery_frontier():
    module = playbook_module()
    kb = module.KB(Log(), seed_target="10.0.0.8", allowed={"10.0.0.8", "10.0.0.9", "10.0.0.10"})
    kb.add_host("10.0.0.8", os="Windows 11")
    kb.add_host("10.0.0.9", os="Windows Server 2022")
    kb.add_host("10.0.0.10", os="Windows Server 2022", dc=True)
    kb.add_host("10.0.0.10", os="", dc=False)  # stale database data must not erase direct DC evidence
    assert [kb.hosts[host]["role"] for host in ("10.0.0.8", "10.0.0.9", "10.0.0.10")] == ["workstation", "server", "domain_controller"]
    first = module.Cred("example.test", "alice", "CaseSensitive", source="seed")
    other = module.Cred("example.test", "alice", "casesensitive", source="seed")
    assert kb.add_cred(first)
    assert kb.add_cred(other)
    assert len(kb.worklist) == 6
    assert [target for _, target in sorted(kb.worklist[:3], key=kb.state_priority)] == ["10.0.0.10", "10.0.0.9", "10.0.0.8"]
    assert not kb.add_cred(first)


def test_anonymous_frontier_is_deduplicated_and_recorded():
    module = playbook_module()
    kb = module.KB(Log(), allowed={"10.0.0.10"})
    kb.add_host("10.0.0.10", dc=True)
    kb.enqueue(None, "10.0.0.10")
    kb.enqueue(None, "10.0.0.10")
    assert kb.worklist == [(None, "10.0.0.10")]
    assert kb.state_parents[None, "10.0.0.10"] is None
    kb.log.base = "/tmp/test"
    report = module.build_report(kb, "10.0.0.10")
    assert report.traversal_tree == [{"principal": "anonymous", "host": "10.0.0.10", "role": "domain_controller", "from_principal": None, "from_host": None}]


def test_tier_zero_requires_authenticated_dc_admin_and_keeps_path():
    module = playbook_module()
    kb = module.KB(Log(), allowed={"10.0.0.10", "10.0.0.20"})
    kb.add_host("10.0.0.10", os="Windows Server", dc=True)
    kb.add_host("10.0.0.20", os="Windows Server", dc=False)
    seed = module.Cred("example.test", "alice", "password")
    kb.add_cred(seed)
    kb.current_state = (seed, "10.0.0.20")
    recovered = module.Cred("example.test", "bob", "new-password", source="share")
    kb.add_cred(recovered)
    kb.note_access(recovered, "10.0.0.20", "smb", SimpleNamespace(authenticated=True, admin=True))
    kb.note_access(recovered, "10.0.0.10", "smb", SimpleNamespace(authenticated=False, admin=True))
    assert not kb.tier_zero_reached
    kb.note_access(recovered, "10.0.0.10", "smb", SimpleNamespace(authenticated=True, admin=True))
    assert kb.tier_zero_reached
    assert not kb.da_reached
    assert [step["type"] for step in kb.tier_zero_path] == ["seed", "credential", "access"]
    assert kb.tier_zero_path[-1]["role"] == "domain_controller"


def test_krbtgt_material_is_not_access_proof():
    module = playbook_module()
    kb = module.KB(Log(), allowed={"10.0.0.10"})
    kb.add_cred(module.Cred("example.test", "krbtgt", ":" + "a" * 32, "hash", source="workspace-db"))
    assert kb.tier_zero_material[0]["material"] == "krbtgt hash"
    assert not kb.tier_zero_reached
    assert not kb.da_reached


def test_cracked_kerberos_hashes_reopen_frontier_for_correct_principal():
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    module._ingest_cracked(kb, "$krb5asrep$23$alice@example.test:checksum$edata:PasswordOne\n"
                               "$krb5tgs$23$*bob$FOREIGN.TEST$service/host*$checksum$data:PasswordTwo\n")
    assert {(cred.domain.casefold(), cred.username, cred.secret) for cred in kb.creds.values()} == {
        ("example.test", "alice", "PasswordOne"), ("foreign.test", "bob", "PasswordTwo")}
    assert len(kb.worklist) == 2


def test_database_hashes_keep_domain_and_local_account_scopes_separate():
    module = playbook_module()
    kb = module.KB(Log(), allowed={"10.0.0.10"})

    class Row:
        def __init__(self, **fields):
            self._mapping = fields

    db = SimpleNamespace(
        get_hosts=lambda: [
            Row(id=1, ip="10.0.0.10", hostname="DC1", os="Windows Server", dc=True, domain="example.test"),
            Row(id=2, ip="10.0.1.20", hostname="OLD1", os="Windows Server", dc=False, domain="example.test"),
        ],
        get_credentials=lambda: [
            Row(id=1, domain="example.test", username="alice", password="a" * 32, credtype="hash", pillaged_from_hostid=1),
            Row(id=2, domain="DC1", username="Administrator", password="b" * 32, credtype="hash", pillaged_from_hostid=1),
        ],
        get_users=lambda: [Row(id=1, domain="example.test", username="alice"),
                           Row(id=2, domain="DC1", username="Administrator")],
        get_admin_relations=lambda: [Row(userid=1, hostid=1)],
        get_loggedin_relations=lambda: [Row(userid=2, hostid=2)],
    )
    module.sync_db(kb, SimpleNamespace(db=db), "smb")
    by_user = {cred.username: cred for cred in kb.creds.values()}
    assert by_user["alice"].local is False
    assert by_user["Administrator"].local is True
    assert all(path[0]["type"] == "workspace" for path in kb.credential_paths.values())
    report = module.build_report(kb, "10.0.0.10")
    assert report.relationship_edges == [
        {"type": "adminTo", "principal": "example.test\\alice", "target": "10.0.0.10",
         "hostname": "DC1", "in_scope": True, "source": "smb_workspace", "user_id": 1, "host_id": 1,
         "verified_in_run": False},
        {"type": "hasSession", "principal": "DC1\\Administrator", "target": "10.0.1.20",
         "hostname": "OLD1", "in_scope": False, "source": "smb_workspace", "user_id": 2, "host_id": 2,
         "verified_in_run": None},
    ]
    assert not kb.tier_zero_reached
    kb.note_access(by_user["alice"], "10.0.0.10", "smb", SimpleNamespace(authenticated=True, admin=True))
    assert module.build_report(kb, "10.0.0.10").relationship_edges[0]["verified_in_run"] is True


def test_directory_host_roles_match_only_same_domain_allowed_hosts(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10", "10.0.1.10"})
    kb.add_host("10.0.0.10", hostname="DC1", domain="example.test", os="Windows 10.0")
    kb.add_host("10.0.1.10", hostname="DC1", domain="foreign.test", os="Windows 10.0")
    data = SimpleNamespace(entries=[{"dNSHostName": "dc1.example.test", "sAMAccountName": "DC1$",
                                     "operatingSystem": "Windows Server 2022", "primaryGroupID": "516"}])
    result = ActionResult("ldap", "query", "10.0.0.10", ResultStatus.SUCCESS, data)
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: result)
    module.ldap_host_roles(kb, SimpleNamespace(connection=SimpleNamespace(targetDomain="example.test")))
    assert kb.hosts["10.0.0.10"]["role"] == "domain_controller"
    assert kb.hosts["10.0.0.10"]["os"] == "Windows Server 2022"
    assert kb.hosts["10.0.1.10"]["role"] != "domain_controller"


def test_domain_admin_proof_requires_computed_membership_and_dc_access(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), allowed={"10.0.0.10"})
    kb.add_host("10.0.0.10", os="Windows Server", dc=True, domain="example.test")
    cred = module.Cred("example.test", "alice", "password")
    kb.add_cred(cred)
    kb.note_access(cred, "10.0.0.10", "smb", SimpleNamespace(authenticated=True, admin=True))
    token = ActionResult("ldap", "token-groups", "10.0.0.10", ResultStatus.SUCCESS,
                         SimpleNamespace(groups_returned=True, principal_sid="S-1-5-21-1-2-3-1000", directory_sids=["S-1-5-21-1-2-3-512"]))
    monkeypatch.setattr(module, "do_module", lambda *args, **kwargs: SimpleNamespace(results=[token]))
    module.verify_domain_admin(kb, cred, "10.0.0.10", SimpleNamespace(authenticated=True))
    assert kb.da_reached
    assert "alice" in kb.da_proof


def test_domain_admin_proof_rejects_foreign_domain_and_missing_membership(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), allowed={"10.0.0.10"})
    kb.add_host("10.0.0.10", os="Windows Server", dc=True, domain="example.test")
    foreign = module.Cred("foreign.test", "alice", "password")
    kb.add_cred(foreign)
    kb.note_access(foreign, "10.0.0.10", "smb", SimpleNamespace(authenticated=True, admin=True))
    monkeypatch.setattr(module, "do_module", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("foreign domain must not be checked")))
    module.verify_domain_admin(kb, foreign, "10.0.0.10", SimpleNamespace(authenticated=True))
    assert not kb.da_reached


def test_run_visits_dc_first_and_stops_at_first_verified_path(monkeypatch):
    module = playbook_module()
    seen = []
    monkeypatch.setattr(module, "Log", lambda target: Log())
    monkeypatch.setattr(module, "preflight_tools", lambda kb: None)

    def discover(kb, host):
        kb.allowed.update({"10.0.0.10", "10.0.0.20", "10.0.0.30"})
        kb.add_host("10.0.0.10", os="Windows Server", dc=True)
        kb.add_host("10.0.0.20", os="Windows Server", dc=False)
        kb.add_host("10.0.0.30", os="Windows 11", dc=False)

    monkeypatch.setattr(module, "discover_hosts", discover)
    monkeypatch.setattr(module, "seed_credentials", lambda kb, host: kb.add_cred(module.Cred("example.test", "alice", "password")))
    monkeypatch.setattr(module, "crack_hashes", lambda kb: None)

    def process(kb, host, cred, target):
        seen.append((cred.principal() if cred else None, target))
        if cred is not None and target == "10.0.0.10":
            kb.note_access(cred, target, "smb", SimpleNamespace(authenticated=True, admin=True))

    monkeypatch.setattr(module, "process_state", process)
    host = SimpleNamespace(target="10.0.0.20", connection_defaults={"domain": "example.test"},
                           defaults=lambda **kwargs: None,
                           finding=lambda name, **kwargs: SimpleNamespace(name=name, **kwargs))
    result = module.run(host)
    assert seen == [(None, "10.0.0.10"), ("example.test\\alice", "10.0.0.10")]
    assert result.ok
    assert result.data.tier_zero_reached
    assert result.data.traversal_tree


def test_delegation_ticket_waits_for_exact_allowed_host_identity(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10", "10.0.0.20"})
    kb.add_host("10.0.0.10", hostname="DC1", domain="example.test", dc=True)
    source = module.Cred("example.test", "svc_web", "password")
    kb.add_cred(source)
    record = SimpleNamespace(source="svc_web", source_type="user", delegation_type="constrained",
                             target="WEB1$", spn="HOST/web1.example.test", protocol_transition=True)
    enumeration = ActionResult("ldap", "delegation", "10.0.0.10", ResultStatus.SUCCESS,
                               SimpleNamespace(delegations=[record]))
    ticket = ActionResult("ldap", "delegation", "10.0.0.10", ResultStatus.SUCCESS,
                          SimpleNamespace(ccache="/tmp/web1.ccache"))
    calls = []

    def module_call(kb, session, name, source, domain, **options):
        calls.append(options)
        return SimpleNamespace(results=[ticket if options.get("user") else enumeration])

    monkeypatch.setattr(module, "do_module", module_call)
    monkeypatch.setattr(module, "ENABLE_DELEGATION_TICKETS", True)
    monkeypatch.setattr(module, "DELEGATE_USER", "alice")
    host = SimpleNamespace(target="10.0.0.10")
    module.ldap_delegation(kb, host, source, object())
    assert len(kb.delegation_edges) == 1
    assert kb.delegation_edges[0]["target_host"] is None
    monkeypatch.setattr(module, "open_session", lambda *args: object())
    root = SimpleNamespace(target="10.0.0.10")
    module.issue_delegation_tickets(kb, root)
    assert len(calls) == 1  # no target identity; no ticket request
    kb.observe_host_identity("10.0.0.20", "WEB1")
    module.issue_delegation_tickets(kb, root)
    assert calls[1]["user"] == "alice"
    assert calls[1]["spn"] == "HOST/web1.example.test"
    assert kb.delegation_tickets[0]["target_host"] == "10.0.0.20"
    module.issue_delegation_tickets(kb, root)
    assert len(calls) == 2  # graph visit gate avoids duplicate ticket issuance


def test_rbcd_host_spn_can_request_scoped_cifs_ticket_after_host_observation(monkeypatch, tmp_path):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10", "10.0.0.20"})
    kb.add_host("10.0.0.10", hostname="DC1", domain="example.test", dc=True)
    source = module.Cred("example.test", "NXC1234$", "", source="machine-account",
                         db_ref=("ldap", 7))
    kb.add_cred(source)
    record = SimpleNamespace(source="NXC1234$", source_type="computer",
                             delegation_type="resource-based constrained", target="WEB1$",
                             spn="HOST/web1.example.test", protocol_transition=False)
    enumeration = ActionResult("ldap", "delegation", "10.0.0.10", ResultStatus.SUCCESS,
                               SimpleNamespace(delegations=[record]))
    cache = tmp_path / "delegated.ccache"
    cache.write_bytes(b"offline fixture")
    ticket = ActionResult("ldap", "delegation", "10.0.0.10", ResultStatus.SUCCESS,
                          SimpleNamespace(ccache=str(cache), expires_at=4102444800))
    requested = []

    def module_call(kb, session, name, step_source, domain, **options):
        if "user" in options:
            requested.append(options["spn"])
            return SimpleNamespace(results=[ticket])
        return SimpleNamespace(results=[enumeration])

    monkeypatch.setattr(module, "do_module", module_call)
    monkeypatch.setattr(module, "open_session", lambda *args: object())
    monkeypatch.setattr(module, "ENABLE_DELEGATION_TICKETS", True)
    monkeypatch.setattr(module, "DELEGATE_USER", "alice")
    root = SimpleNamespace(target="10.0.0.10")
    module.ldap_delegation(kb, root, source, object())
    kb.acl_assessments.append({"target_type": "computer", "target_name": "WEB1$",
                               "target_dn": "CN=WEB1,CN=Computers,DC=example,DC=test",
                               "source_host": "10.0.0.10", "principal": "example.test\\operator",
                               "next_action": {"completed": True, "options": {"source": "NXC1234$"}}})
    module.issue_delegation_tickets(kb, root)
    assert requested == []
    kb.observe_host_identity("10.0.0.20", "WEB1")
    module.issue_delegation_tickets(kb, root)
    assert "cifs/web1.example.test" in requested
    cifs = next(ticket for ticket in kb.delegation_tickets if ticket["spn"] == "cifs/web1.example.test")
    assert cifs["alias_of"] == "HOST/web1.example.test"
    assert cifs["target_host"] == "10.0.0.20"
    assert cifs["expires_at"] == 4102444800
    assert cifs["credential_queued"]
    assert any(credential.kind == "ccache" and credential.target_scope == "10.0.0.20"
               and credential.protocols == ("smb",) for credential in kb.creds.values())
    delegated = next(credential for credential in kb.creds.values() if credential.kind == "ccache")
    assert delegated.expires_at == 4102444800
    path = kb.credential_paths[delegated.key()]
    assert [step["type"] for step in path[-2:]] == ["rbcd_grant", "credential"]
    assert path[-2]["principal"] == "example.test\\operator"
    assert path[-1]["host"] == "10.0.0.10"
    assert path[-1]["technique"] == "delegation:example.test\\NXC1234$"
    assert not kb.tier_zero_reached
    module.issue_delegation_tickets(kb, root)
    assert requested.count("cifs/web1.example.test") == 1


def test_delegation_never_matches_foreign_domain_or_ambiguous_host():
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.20", "10.0.0.21"})
    kb.observe_host_identity("10.0.0.20", "WEB1")
    kb.observe_host_identity("10.0.0.21", "WEB1")
    record = SimpleNamespace(spn="HOST/web1.example.test", target="WEB1$")
    assert module.match_delegation_target(kb, record) is None
    kb.observed_hostnames["10.0.0.21"] = {"WEB2"}
    assert module.match_delegation_target(kb, record) == "10.0.0.20"
    record.spn = "HOST/web1.foreign.test"
    assert module.match_delegation_target(kb, record) is None


def test_delegated_ldap_and_sql_tickets_reenter_only_their_service(monkeypatch, tmp_path):
    module = playbook_module()
    monkeypatch.setattr(module, "DELEGATE_USER", "alice")
    for service, account, protocol in (("ldap", "DC1$", "ldap"),
                                       ("MSSQLSvc", "svc_sql", "mssql"),
                                       ("HTTP", "svc_web", None)):
        cache = tmp_path / f"{service}.ccache"
        cache.write_bytes(b"test cache path")
        kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10", "10.0.0.20"})
        kb.add_host("10.0.0.10", hostname="KDC", dc=True, domain="example.test")
        kb.observe_host_identity("10.0.0.20", "DC1" if service == "ldap" else "SQL1")
        source = module.Cred("example.test", "svc_delegate", "password")
        record = SimpleNamespace(source="svc_delegate", target=account,
                                 spn=f"{service}/{'dc1' if service == 'ldap' else 'sql1'}.example.test")
        kb.delegation_candidates.append((source, "10.0.0.10", record, record.spn))
        ticket = ActionResult("ldap", "delegation", "10.0.0.10", ResultStatus.SUCCESS,
                              SimpleNamespace(ccache=str(cache)))
        monkeypatch.setattr(module, "open_session", lambda *args: object())
        monkeypatch.setattr(module, "do_module", lambda *args, ticket=ticket, **kwargs: SimpleNamespace(results=[ticket]))
        module.issue_delegation_tickets(kb, SimpleNamespace(target="10.0.0.10"))
        artifact = kb.delegation_tickets[0]
        assert artifact["target_host"] == "10.0.0.20"
        assert artifact["protocols"] == ((protocol,) if protocol else None)
        assert artifact["credential_queued"] is (protocol is not None)
        if protocol:
            assert [(cred.protocols, target) for cred, target in kb.worklist] == [((protocol,), "10.0.0.20")]
        else:
            assert not kb.worklist


def test_service_ccache_traverses_only_matching_protocol(monkeypatch, tmp_path):
    module = playbook_module()
    for protocol in ("ldap", "mssql"):
        cache = tmp_path / f"{protocol}.ccache"
        cache.write_bytes(b"test cache path")
        kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10", "10.0.0.20"})
        kb.add_host("10.0.0.20", dc=(protocol == "ldap"), domain="example.test")
        cred = module.Cred("example.test", "alice", str(cache), "ccache", target_scope="10.0.0.20",
                           protocols=(protocol,), kdc_host="10.0.0.10")
        assert kb.add_cred(cred)
        seen = []
        session = SimpleNamespace(authenticated=True, admin=False, db=None)

        def connect(kb, host, name, cred, seen=seen, session=session):
            seen.append(name)
            return session

        monkeypatch.setattr(module, "open_session", connect)
        for name in ("ldap_enumerate", "ldap_host_roles", "ldap_roast", "ldap_delegation",
                     "ldap_acl_assessment", "ldap_secrets", "verify_domain_admin",
                     "mssql_sweep", "sync_db", "crack_hashes"):
            monkeypatch.setattr(module, name, lambda *args, **kwargs: None)
        module.process_state(kb, SimpleNamespace(target="10.0.0.20"), cred, "10.0.0.20")
        assert seen == [protocol]
        assert kb.access_edges[0]["protocol"] == protocol
        assert not kb.tier_zero_reached


def test_cifs_ticket_reenters_only_matching_host_and_restores_cache(monkeypatch, tmp_path):
    module = playbook_module()
    cache = tmp_path / "alice.ccache"
    cache.write_bytes(b"test cache path")
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10", "10.0.0.20"})
    cred = module.Cred("example.test", "alice", str(cache), "ccache", source="delegation:svc",
                       target_scope="10.0.0.20", protocols=("smb",), kdc_host="10.0.0.10")
    assert kb.add_cred(cred)
    assert kb.worklist == [(cred, "10.0.0.20")]
    monkeypatch.setenv("KRB5CCNAME", "previous-cache")
    seen = []

    def smb(**kwargs):
        seen.append((kwargs, module.os.environ.get("KRB5CCNAME")))
        return SimpleNamespace(ok=True, authenticated=True, admin=False,
                               connection=SimpleNamespace(hostname="WEB1", isdc=False))

    assert module.open_session(kb, SimpleNamespace(target="10.0.0.20", smb=smb), "smb", cred) is not None
    assert seen[0][0]["use_kcache"] is True
    assert seen[0][0]["kdcHost"] == "10.0.0.10"
    assert seen[0][1] == str(cache)
    assert module.os.environ["KRB5CCNAME"] == "previous-cache"
    assert module.open_session(kb, SimpleNamespace(target="10.0.0.10", smb=smb), "smb", cred) is None
    assert len(seen) == 1


def test_gmsa_action_returns_typed_keys_and_graph_reuses_them(monkeypatch):
    ldap_module = ProtocolLoader().load_protocol(str(Path(__file__).parents[1] / "nxc" / "protocols" / "ldap.py"))
    monkeypatch.setattr(ldap_module, "parse_result_attributes", lambda rows: rows)
    logger = SimpleNamespace(display=lambda *args: None, debug=lambda *args: None,
                             highlight=lambda *args: None)
    account = {"sAMAccountName": "svc_backup$", "msDS-ManagedPassword": b"managed-password"}
    connection = SimpleNamespace(
        logger=logger, search=lambda *args, **kwargs: [account], last_search_error=None,
        gmsa_compute_secrets=lambda *args: ("a" * 32, "b" * 32, "c" * 64),
        playbook_mode=True, host="10.0.0.10", domain="example.test",
    )
    result = ldap_module.ldap.gmsa(connection)
    assert result.status is ResultStatus.SUCCESS
    assert result.data.accounts[0].account == "svc_backup$"
    assert result.data.accounts[0].password_readable
    assert result.data.accounts[0].rc4 == "a" * 32
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", kdc_host="10.0.0.10",
                   allowed={"10.0.0.10", "10.0.0.20"})
    module.harvest_gmsa_result(kb, result, "example.test")
    assert {(cred.username, cred.kind) for cred in kb.creds.values()} == {
        ("svc_backup$", "hash"), ("svc_backup$", "aes")}
    assert {target for _, target in kb.worklist} == kb.allowed
    assert all(cred.domain == "example.test" and cred.source == "gmsa" for cred in kb.creds.values())


def test_unreadable_gmsa_never_enters_credential_frontier(monkeypatch):
    ldap_module = ProtocolLoader().load_protocol(str(Path(__file__).parents[1] / "nxc" / "protocols" / "ldap.py"))
    monkeypatch.setattr(ldap_module, "parse_result_attributes", lambda rows: rows)
    logger = SimpleNamespace(display=lambda *args: None, debug=lambda *args: None,
                             highlight=lambda *args: None)
    connection = SimpleNamespace(
        logger=logger, search=lambda *args, **kwargs: [{"sAMAccountName": "svc_unreadable$"}],
        last_search_error=None, playbook_mode=True, host="10.0.0.10", domain="example.test",
    )
    result = ldap_module.ldap.gmsa(connection)
    assert result.status is ResultStatus.SUCCESS
    assert not result.data.accounts[0].password_readable
    assert result.data.accounts[0].rc4 is None
    module = playbook_module()
    kb = module.KB(Log(), allowed={"10.0.0.10"})
    module.harvest_gmsa_result(kb, result, "example.test")
    assert not kb.creds


def test_invalid_gmsa_blob_keeps_account_without_credential(monkeypatch):
    ldap_module = ProtocolLoader().load_protocol(str(Path(__file__).parents[1] / "nxc" / "protocols" / "ldap.py"))
    monkeypatch.setattr(ldap_module, "parse_result_attributes", lambda rows: rows)
    messages = []

    def invalid_blob(*args):
        raise ValueError("invalid managed-password blob")

    connection = SimpleNamespace(
        logger=SimpleNamespace(display=lambda *args: None, debug=lambda *args: None,
                               highlight=lambda *args: None, fail=messages.append),
        search=lambda *args, **kwargs: [{"sAMAccountName": "svc_broken$", "msDS-ManagedPassword": b"bad"}],
        gmsa_compute_secrets=invalid_blob, last_search_error=None,
        playbook_mode=True, host="10.0.0.10", domain="example.test",
    )
    result = ldap_module.ldap.gmsa(connection)
    assert result.status is ResultStatus.FAILED
    assert result.data.accounts[0].account == "svc_broken$"
    assert not result.data.accounts[0].password_readable
    assert "invalid managed-password blob" in messages[0]
    module = playbook_module()
    kb = module.KB(Log(), allowed={"10.0.0.10"})
    module.harvest_gmsa_result(kb, result, "example.test")
    assert not kb.creds


def test_domain_root_acl_candidate_requires_both_computed_replication_rights(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    cred = module.Cred("example.test", "alice", "password")
    kb.add_cred(cred)
    sid = "S-1-5-21-1-2-3-1000"
    guids = ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
    aces = [{"index": index, "supported": True, "flags": 0, "access": "allowed",
             "trustee_sid": sid, "mask": 0x100, "object_type": guid} for index, guid in enumerate(guids)]
    descriptor = {"dacl_present": True, "null_dacl": False, "owner_sid": "other", "aces": aces}
    token = ActionResult("ldap", "token-groups", "10.0.0.10", ResultStatus.SUCCESS,
                         SimpleNamespace(groups_returned=True, directory_sids=[sid]))
    dacl = ActionResult("ldap", "daclread", "10.0.0.10", ResultStatus.SUCCESS,
                        SimpleNamespace(objects=[{"dn": "DC=example,DC=test", "sid": None,
                                                  "descriptor": descriptor, "error": None}]))
    calls = []

    def module_call(kb, session, name, source, domain, **options):
        calls.append((name, options))
        return SimpleNamespace(results=[token if name == "token-groups" else dacl])

    monkeypatch.setattr(module, "do_module", module_call)
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: None)
    session = SimpleNamespace(connection=SimpleNamespace(baseDN="DC=example,DC=test", targetDomain="example.test"))
    host = SimpleNamespace(target="10.0.0.10")
    module.ldap_acl_assessment(kb, host, cred, session)
    assert [name for name, _ in calls] == ["token-groups", "daclread"]
    assert calls[1][1] == {"target_dn": "DC=example,DC=test", "ace_type": "all"}
    assert kb.acl_assessments[0]["decision"] == "candidate"
    assert {right["decision"] for right in kb.acl_assessments[0]["rights"].values()} == {"allowed"}
    assert kb.findings[-1].startswith("conditional DCSync candidate")
    assert not kb.tier_zero_reached
    module.ldap_acl_assessment(kb, host, cred, session)
    assert len(calls) == 2
    descriptor["aces"].insert(0, {**aces[1], "index": 2, "access": "denied"})
    other = module.Cred("example.test", "alice", "other-password")
    kb.add_cred(other)
    module.ldap_acl_assessment(kb, host, other, session)
    assert kb.acl_assessments[-1]["decision"] == "denied"
    assert not kb.tier_zero_reached


def test_domain_root_acl_unknown_without_computed_sids(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    cred = module.Cred("example.test", "alice", "password")
    token = ActionResult("ldap", "token-groups", "10.0.0.10", ResultStatus.FAILED,
                         SimpleNamespace(groups_returned=False, directory_sids=[]), error="tokenGroups unavailable")
    calls = []

    def module_call(kb, session, name, source, domain, **options):
        calls.append(name)
        return SimpleNamespace(results=[token])

    monkeypatch.setattr(module, "do_module", module_call)
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: None)
    session = SimpleNamespace(connection=SimpleNamespace(baseDN="DC=example,DC=test", targetDomain="example.test"))
    module.ldap_acl_assessment(kb, SimpleNamespace(target="10.0.0.10"), cred, session)
    assert calls == ["token-groups"]
    assert kb.acl_assessments[0]["decision"] == "unknown"
    assert not kb.acl_assessments[0]["rights"]


def test_privileged_group_acl_add_member_path_is_a_candidate_only(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    cred = module.Cred("example.test", "alice", "password")
    sid = "S-1-5-21-1-2-3-1000"
    group_sid = "S-1-5-21-1-2-3-512"
    group_dn = "CN=Domain Admins,CN=Users,DC=example,DC=test"
    token = SimpleNamespace(principal_sid=sid, directory_sids=[sid])
    query = ActionResult("ldap", "query", "10.0.0.10", ResultStatus.SUCCESS,
                         SimpleNamespace(entries=[
                             {"objectSid": group_sid,
                              "sAMAccountName": "Domain Admins", "objectClass": ["top", "group"]},
                             {"objectSid": group_sid, "distinguishedName": "/tmp/unsafe",
                              "sAMAccountName": "unsafe", "objectClass": ["group"]},
                         ], distinguished_names=[group_dn, "/tmp/unsafe"]))
    descriptor = {"dacl_present": True, "null_dacl": False, "owner_sid": "other", "aces": [
        {"index": 0, "supported": True, "flags": 0, "access": "allowed", "trustee_sid": sid,
         "mask": 0x20, "object_type": "bf9679c0-0de6-11d0-a285-00aa003049e2"},
    ]}
    dacl = ActionResult("ldap", "daclread", "10.0.0.10", ResultStatus.SUCCESS,
                        SimpleNamespace(objects=[{"dn": group_dn, "sid": group_sid,
                                                  "descriptor": descriptor, "error": None}]))
    calls = []
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: query)

    def module_call(kb, session, name, source, domain, **options):
        calls.append((name, options))
        return SimpleNamespace(results=[dacl])

    monkeypatch.setattr(module, "do_module", module_call)
    module.ldap_privileged_group_assessment(kb, SimpleNamespace(target="10.0.0.10"), cred,
                                             object(), token, ["S-1-1-0", "S-1-5-11"], "DC=example,DC=test")
    assert calls == [("daclread", {"target_dn": group_dn, "ace_type": "all"})]
    assert len(kb.acl_assessments) == 1
    record = kb.acl_assessments[0]
    assert record["target_type"] == "group"
    assert record["decision"] == "candidate"
    assert record["rights"]["WriteMembers"]["decision"] == "allowed"
    assert record["next_action"] == {"module": "modify-group",
                                      "options": {"group": "Domain Admins", "group_dn": group_dn,
                                                  "user": "alice"},
                                      "executed": False}
    assert not kb.tier_zero_reached


def test_group_control_requires_opt_in_and_fresh_dc_admin_proof(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    kb.add_host("10.0.0.10", dc=True, domain="example.test")
    cred = module.Cred("example.test", "alice", "password")
    kb.add_cred(cred)
    dn = "CN=Domain Admins,CN=Users,DC=example,DC=test"
    record = {"target_name": "Domain Admins", "target_dn": dn,
              "next_action": {"module": "modify-group", "options": {"group": "Domain Admins", "group_dn": dn,
                                                              "user": "alice"},
                              "executed": False}}
    calls = []

    def module_call(kb, session, name, source, domain, **options):
        calls.append((name, options))
        data = SimpleNamespace(completed=True, group_dn=dn, user="alice")
        return SimpleNamespace(results=[ActionResult("ldap", name, "10.0.0.10", ResultStatus.SUCCESS, data)])

    monkeypatch.setattr(module, "do_module", module_call)
    monkeypatch.setattr(module, "open_session", lambda kb, host, protocol, cred, **kwargs: SimpleNamespace(authenticated=True, admin=True))
    monkeypatch.setattr(module, "verify_domain_admin", lambda *args: calls.append(("verify-domain-admin", {})))
    host = SimpleNamespace(target="10.0.0.10")
    monkeypatch.setattr(module, "ENABLE_GROUP_WRITES", False)
    module.execute_group_control(kb, host, cred, object(), record)
    assert calls == []
    assert not record["next_action"]["executed"]
    monkeypatch.setattr(module, "ENABLE_GROUP_WRITES", True)
    module.execute_group_control(kb, host, cred, object(), record)
    assert calls == [("modify-group", {"group": "Domain Admins", "group_dn": dn, "user": "alice"}),
                     ("verify-domain-admin", {})]
    assert record["next_action"]["completed"]
    assert record["next_action"]["verified_admin"]
    assert kb.tier_zero_reached
    assert [step["type"] for step in kb.tier_zero_path] == ["seed", "group_membership", "access"]


def test_group_control_success_without_fresh_admin_remains_unverified(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    kb.add_host("10.0.0.10", dc=True, domain="example.test")
    cred = module.Cred("example.test", "alice", "password")
    kb.add_cred(cred)
    dn = "CN=Domain Admins,CN=Users,DC=example,DC=test"
    record = {"target_name": "Domain Admins", "target_dn": dn,
              "next_action": {"module": "modify-group", "options": {"group": "Domain Admins", "group_dn": dn,
                                                              "user": "alice"},
                              "executed": False}}
    data = SimpleNamespace(completed=True, group_dn=dn, user="alice")
    monkeypatch.setattr(module, "ENABLE_GROUP_WRITES", True)
    monkeypatch.setattr(module, "do_module", lambda *args, **kwargs: SimpleNamespace(results=[
        ActionResult("ldap", "modify-group", "10.0.0.10", ResultStatus.SUCCESS, data)]))
    monkeypatch.setattr(module, "open_session", lambda *args, **kwargs: SimpleNamespace(authenticated=True, admin=False))
    module.execute_group_control(kb, SimpleNamespace(target="10.0.0.10"), cred, object(), record)
    assert record["next_action"]["completed"]
    assert not record["next_action"]["verified_admin"]
    assert not kb.tier_zero_reached


def test_target_user_reset_acl_is_a_conditional_candidate(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    cred = module.Cred("example.test", "alice", "password")
    dn = "CN=Target,CN=Users,DC=example,DC=test"
    sid = "S-1-5-21-1-2-3-1000"
    token = SimpleNamespace(directory_sids=[sid])
    query = ActionResult("ldap", "query", "10.0.0.10", ResultStatus.SUCCESS,
                         SimpleNamespace(entries=[{"objectSid": "S-1-5-21-1-2-3-1100",
                                                   "sAMAccountName": "da.user", "objectClass": ["top", "user"]}],
                                         distinguished_names=[dn]))
    descriptor = {"dacl_present": True, "null_dacl": False, "owner_sid": "other", "aces": [
        {"index": 0, "supported": True, "flags": 0, "access": "allowed", "trustee_sid": sid,
         "mask": 0x100, "object_type": "00299570-246d-11d0-a768-00aa006e0529"},
    ]}
    dacl = ActionResult("ldap", "daclread", "10.0.0.10", ResultStatus.SUCCESS,
                        SimpleNamespace(objects=[{"dn": dn, "sid": "S-1-5-21-1-2-3-1100",
                                                  "descriptor": descriptor, "error": None}]))
    monkeypatch.setattr(module, "RESET_TARGET_USER", "da.user")
    monkeypatch.setattr(module, "ENABLE_PASSWORD_RESET", False)
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: query)
    monkeypatch.setattr(module, "do_module", lambda *args, **kwargs: SimpleNamespace(results=[dacl]))
    module.ldap_user_reset_assessment(kb, SimpleNamespace(target="10.0.0.10"), cred,
                                      object(), token, ["S-1-5-11"], "DC=example,DC=test")
    assert len(kb.acl_assessments) == 1
    record = kb.acl_assessments[0]
    assert record["target_type"] == "user"
    assert record["decision"] == "candidate"
    assert record["rights"]["ForceChangePassword"]["decision"] == "allowed"
    assert record["next_action"] == {"module": "change-password", "options": {"user": "da.user"},
                                      "executed": False}
    assert not kb.creds


def test_acknowledged_password_reset_reopens_credential_frontier(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10", "10.0.0.20"})
    kb.add_host("10.0.0.10", dc=True, domain="example.test")
    actor = module.Cred("example.test", "alice", "old-password")
    kb.add_cred(actor)
    kb.current_state = (actor, "10.0.0.10")
    dn = "CN=Target,CN=Users,DC=example,DC=test"
    record = {"target_name": "da.user", "target_dn": dn,
              "next_action": {"module": "change-password", "options": {"user": "da.user"}, "executed": False}}
    data = SimpleNamespace(completed=True, stored=True, username="da.user", domain="example.test",
                           credential_kind="plaintext", new_secret="replacement", credential_id=42)
    monkeypatch.setattr(module, "ENABLE_PASSWORD_RESET", True)
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda length: "replacement")
    monkeypatch.setattr(module, "open_session", lambda *args: SimpleNamespace(authenticated=True))
    monkeypatch.setattr(module, "do_module", lambda *args, **kwargs: SimpleNamespace(results=[
        ActionResult("smb", "change-password", "10.0.0.10", ResultStatus.FAILED, data,
                     error="Closing SAMR connection: cleanup failed")]))
    module.execute_user_password_reset(kb, SimpleNamespace(target="10.0.0.10"), actor, record)
    assert record["next_action"]["executed"]
    assert record["next_action"]["credential_queued"]
    assert record["next_action"]["credential_ref"] == {"protocol": "smb", "id": 42}
    assert {cred.username for cred in kb.creds.values()} == {"alice", "da.user"}
    assert next(cred for cred in kb.creds.values() if cred.username == "da.user").db_ref == ("smb", 42)
    assert {target for cred, target in kb.worklist if cred and cred.username == "da.user"} == {"10.0.0.10", "10.0.0.20"}
    assert not kb.tier_zero_reached


def test_database_backed_credential_is_reused_by_reference(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    cred = module.Cred("example.test", "da.user", "", db_ref=("smb", 42))
    assert kb.add_cred(cred)
    seen = []
    session = SimpleNamespace(ok=True, authenticated=True,
                              connection=SimpleNamespace(hostname="DC1", isdc=True), result=None)

    class Host:
        target = "10.0.0.10"

        def credential(self, protocol, credential_id):
            seen.append((protocol, credential_id))
            return (protocol, credential_id)

        def smb(self, **options):
            seen.append(options)
            return session

    monkeypatch.setattr(module, "run_bounded", lambda fn, *args: (fn(), False))
    assert module.open_session(kb, Host(), "smb", cred) is session
    assert seen == [("smb", 42), {"credential": ("smb", 42), "no_smbv1": True}]


def test_machine_quota_creation_queues_database_reference_once(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10", "10.0.0.20"})
    kb.add_host("10.0.0.10", dc=True, domain="example.test")
    actor = module.Cred("example.test", "alice", "password")
    kb.add_cred(actor)
    kb.current_state = (actor, "10.0.0.10")
    quota = SimpleNamespace(results=[ActionResult("ldap", "maq", "10.0.0.10", ResultStatus.SUCCESS,
                                                  SimpleNamespace(quota=10))])
    machine = SimpleNamespace(completed=True, stored=True, operation="add", account="NXCABCD1234$",
                              domain="example.test", password="replacement", credential_id=52)
    calls = []

    def module_call(kb, session, module_name, source, domain, **options):
        calls.append((module_name, options))
        return SimpleNamespace(results=[ActionResult("ldap", module_name, "10.0.0.10", ResultStatus.SUCCESS, machine)])

    monkeypatch.setattr(module, "ENABLE_MACHINE_CREATE", True)
    monkeypatch.setattr(module.secrets, "token_hex", lambda length: "abcd1234")
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda length: "replacement")
    monkeypatch.setattr(module, "do_module", module_call)
    host = SimpleNamespace(target="10.0.0.10")
    session = SimpleNamespace(connection=SimpleNamespace(domain="example.test"))
    module.maybe_create_machine_account(kb, host, actor, session, quota)
    module.maybe_create_machine_account(kb, host, actor, session, quota)
    assert calls == [("add-computer", {"name": "NXCABCD1234", "password": "replacement"})]
    assert kb.machine_account_created
    assert kb.machine_account_actions[0]["credential_ref"] == {"protocol": "ldap", "id": 52}
    created = next(cred for cred in kb.creds.values() if cred.username == "NXCABCD1234$")
    assert created.db_ref == ("ldap", 52)
    assert {target for cred, target in kb.worklist if cred == created} == kb.allowed
    assert not kb.tier_zero_reached


def test_machine_creation_requires_opt_in_and_positive_quota(monkeypatch):
    module = playbook_module()
    kb = module.KB(Log(), default_domain="example.test", allowed={"10.0.0.10"})
    kb.add_host("10.0.0.10", dc=True, domain="example.test")
    actor = module.Cred("example.test", "alice", "password")
    host = SimpleNamespace(target="10.0.0.10")
    quota = SimpleNamespace(results=[ActionResult("ldap", "maq", "10.0.0.10", ResultStatus.SUCCESS,
                                                  SimpleNamespace(quota=0))])
    monkeypatch.setattr(module, "do_module", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not create")))
    monkeypatch.setattr(module, "ENABLE_MACHINE_CREATE", False)
    module.maybe_create_machine_account(kb, host, actor, object(), quota)
    monkeypatch.setattr(module, "ENABLE_MACHINE_CREATE", True)
    module.maybe_create_machine_account(kb, host, actor, object(), quota)
    assert not kb.machine_account_actions
