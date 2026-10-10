"""SQL inventory edges from typed NetExec results remain separate from access."""

from pathlib import Path
from types import SimpleNamespace

from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import load_playbook


SCRIPT = Path(__file__).parents[1] / "examples" / "playbooks" / "getDomAdmin.py"


def playbook_module():
    run = load_playbook(SCRIPT)
    return __import__(run.__module__, fromlist=["KB"])


def setup_graph():
    module = playbook_module()
    log = SimpleNamespace(good=lambda *args, **kwargs: None)
    kb = module.KB(log, allowed={"10.0.0.20", "10.0.0.21", "10.0.0.22"})
    kb.observe_host_identity("10.0.0.21", "sql2.example.test")
    kb.observe_host_identity("10.0.0.22", "sql2")
    host = SimpleNamespace(target="10.0.0.20")
    cred = module.Cred("example.test", "analyst", "password")
    return module, kb, host, cred


def test_sql_inventory_preserves_permissions_and_scope_without_access():
    module, kb, host, cred = setup_graph()
    login = ActionResult("mssql", "query", host.target, ResultStatus.SUCCESS,
                         SimpleNamespace(columns=["login", "sysadmin"], rows=[("EXAMPLE\\analyst", 0)]))
    permissions = ActionResult("mssql", "enum_impersonate", host.target, ResultStatus.SUCCESS,
                               SimpleNamespace(permissions=[
                                   {"grantee": "EXAMPLE\\analyst", "permission_name": "IMPERSONATE",
                                    "state_desc": "GRANT", "target_login": "sa"},
                                   {"grantee": "EXAMPLE\\analyst", "permission_name": "IMPERSONATE",
                                    "state_desc": "DENY", "target_login": "operator"},
                               ]))
    links = ActionResult("mssql", "enum_links", host.target, ResultStatus.SUCCESS,
                         SimpleNamespace(servers=[{"SRV_NAME": "sql2.example.test\\INSTANCE"},
                                                  {"SRV_NAME": "external.example.test"}],
                                         login_mappings=[{"Linked Server": "sql2.example.test\\INSTANCE",
                                                          "Local Login": "EXAMPLE\\analyst", "Remote Login": "remote_reader"}],
                                         login_mappings_queried=True))
    for result in (login, permissions, links, links):
        module.record_mssql_observations(kb, host, cred, result)
    assert len(kb.sql_edges) == 6
    sql_login = next(edge for edge in kb.sql_edges if edge["type"] == "sqlLogin")
    assert sql_login["sysadmin"] is False
    assert sql_login["observed_by"] == cred.principal()
    rights = [edge for edge in kb.sql_edges if edge["type"] == "sqlImpersonate"]
    assert [edge["candidate"] for edge in rights] == [True, False]
    links = [edge for edge in kb.sql_edges if edge["type"] == "sqlLinkedServer"]
    assert links[0]["target_host"] == "10.0.0.21"
    assert links[0]["in_scope"]
    assert links[1]["target_host"] is None
    assert not links[1]["in_scope"]
    assert not kb.access_edges
    assert not kb.tier_zero_reached
    kb.log.base = "/tmp/sql-graph-test"
    report = module.build_report(kb, host.target)
    assert len(report.sql_edges) == 6


def test_sql_edges_ignore_failed_wrong_target_and_ambiguous_hosts():
    module, kb, host, cred = setup_graph()
    kb.observe_host_identity("10.0.0.22", "sql2.example.test")
    assert module.match_sql_link_target(kb, "sql2.example.test") is None
    partial = ActionResult("mssql", "enum_links", host.target, ResultStatus.FAILED,
                           SimpleNamespace(servers=[{"SRV_NAME": "sql2.example.test"}],
                                           login_mappings=[], login_mappings_queried=False), error="SQL error")
    wrong_target = ActionResult("mssql", "query", "10.0.0.99", ResultStatus.SUCCESS,
                                SimpleNamespace(columns=["login", "sysadmin"], rows=[("sa", 1)]))
    wrong_protocol = ActionResult("ldap", "query", host.target, ResultStatus.SUCCESS,
                                  SimpleNamespace(columns=["login", "sysadmin"], rows=[("sa", 1)]))
    for result in (partial, wrong_target, wrong_protocol):
        module.record_mssql_observations(kb, host, cred, result)
    assert kb.sql_edges == []


def test_mssql_sweep_wires_typed_results_into_graph(monkeypatch):
    module, kb, host, cred = setup_graph()
    query = ActionResult("mssql", "query", host.target, ResultStatus.SUCCESS,
                         SimpleNamespace(columns=["login", "sysadmin"], rows=[("sa", 1)]))
    links = ActionResult("mssql", "enum_links", host.target, ResultStatus.SUCCESS,
                         SimpleNamespace(servers=[{"SRV_NAME": "sql2.example.test"}],
                                         login_mappings=[], login_mappings_queried=False))
    permissions = ActionResult("mssql", "enum_impersonate", host.target, ResultStatus.SUCCESS,
                               SimpleNamespace(permissions=[{"grantee": "reader", "permission_name": "IMPERSONATE",
                                                             "state_desc": "GRANT", "target_login": "sa"}]))
    called = []
    monkeypatch.setattr(module, "do_action", lambda *args, **kwargs: query)

    def loaded(kb, session, name, source, domain, **options):
        called.append(name)
        return SimpleNamespace(results=[links if name == "enum_links" else permissions])

    monkeypatch.setattr(module, "do_module", loaded)
    monkeypatch.setattr(module, "ENABLE_SQL_DUMP", False)
    module.mssql_sweep(kb, host, cred, object())
    assert called == ["enum_links", "enum_impersonate", "mssql_priv"]
    assert {edge["type"] for edge in kb.sql_edges} == {"sqlLogin", "sqlLinkedServer", "sqlImpersonate"}
