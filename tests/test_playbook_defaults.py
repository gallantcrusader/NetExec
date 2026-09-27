"""CLI defaults reach supported protocols without breaking protocol overrides."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks import runner


@pytest.mark.parametrize(("protocol", "options", "domain"), [
    ("smb", {}, "north.example"),
    ("ldap", {"domain": "essos.example"}, "essos.example"),
    ("smb", {"local_auth": True}, None),
    ("ssh", {}, None),
])
def test_connection_defaults_and_overrides(monkeypatch, protocol, options, domain):
    class OfflineProtocol:
        def __init__(self, args, db, target, defer_flow=False):
            self.args = args
            self.host = target
            self.transport_open = False

        def open_session(self, anonymous=False):
            return False

        def close_session(self):
            pass

    host = runner.HostContext("offline.invalid", [], {"domain": "north.example", "dns_server": "192.0.2.10"})
    host.protocols = {protocol: {"path": "protocol", "dbpath": "database"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(**{protocol: OfflineProtocol}) if path == "protocol" else SimpleNamespace(database=lambda engine: object()))
    monkeypatch.setattr(runner, "create_db_engine", lambda path: Mock())
    result = host.connect(protocol, stop_on_error=False, **options)
    assert getattr(result.args, "domain", None) == domain
    assert result.args.dns_server == "192.0.2.10"
    assert host.connection_defaults["domain"] == "north.example"
    host.close()


def test_cli_domain_and_dns_defaults(tmp_path):
    script = tmp_path / "defaults.py"
    script.write_text("def run(host):\n    assert host.connection_defaults == {'domain': 'north.example', 'dns_server': '192.0.2.10'}\n")
    assert runner.main([str(script), "192.0.2.11", "-d", "north.example", "--dns-server", "192.0.2.10", "--results", str(tmp_path / "results.json")]) == 0


def test_cli_kerberos_defaults_reach_playbook(tmp_path):
    script = tmp_path / "kerberos.py"
    script.write_text("def run(host):\n    assert host.connection_defaults == {'domain': 'north.example', 'kerberos': True, 'kdcHost': '192.0.2.10'}\n")
    assert runner.main([str(script), "192.0.2.11", "-d", "north.example", "-k", "--kdcHost", "192.0.2.10", "--results", str(tmp_path / "results.json")]) == 0


def test_kerberos_default_applies_to_ldap_connection(monkeypatch):
    class OfflineLDAP:
        def __init__(self, args, db, target, defer_flow=False):
            self.args = args
            self.host = target
            self.transport_open = False

        def open_session(self, anonymous=False):
            return False

        def close_session(self):
            pass

    host = runner.HostContext("offline.invalid", [], {"kerberos": True, "kdcHost": "192.0.2.10"})
    host.protocols = {"ldap": {"path": "protocol", "dbpath": "database"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(ldap=OfflineLDAP) if path == "protocol" else SimpleNamespace(database=lambda engine: object()))
    monkeypatch.setattr(runner, "create_db_engine", lambda path: Mock())
    session = host.ldap(stop_on_error=False)
    assert session.args.kerberos is True
    assert session.args.kdcHost == "192.0.2.10"
    host.close()
