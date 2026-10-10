"""Delegation ticket lifetime is carried into playbooks and checked before use."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from nxc.modules import delegation
from nxc.playbooks.results import ResultStatus
from nxc.playbooks.runner import load_playbook


SCRIPT = Path(__file__).parents[1] / "examples" / "playbooks" / "getDomAdmin.py"


def playbook_module():
    run = load_playbook(SCRIPT)
    return __import__(run.__module__, fromlist=["KB"])


def test_requested_ticket_exposes_cache_end_time_and_rejects_expiry(monkeypatch, tmp_path):
    module = delegation.NXCModule()
    module.user = "alice"
    module.spn = "cifs/web1.example.test"
    module.output = str(tmp_path / "ticket.ccache")
    connection = SimpleNamespace(domain="example.test", hostname="DC1", username="svc", password="secret",
                                 nthash="", lmhash="", aesKey="", kdcHost="10.0.0.10", host="10.0.0.10",
                                 use_kcache=False)
    monkeypatch.setattr(delegation, "kerberos_login_with_S4U", lambda *args: ({"KDC_REP": b"ticket"}, object()))
    monkeypatch.setattr(delegation, "time", lambda: 1000)

    class Cache:
        endtime = 2000

        def __init__(self):
            self.credentials = []

        def fromTGS(self, ticket, old_key, session_key):
            self.credentials = [{"time": {"endtime": self.endtime}}]

        def saveFile(self, path):
            Path(path).write_bytes(b"ccache")

    monkeypatch.setattr(delegation, "CCache", Cache)
    path, endtime = module.request_ticket(connection)
    assert path == tmp_path / "ticket.ccache"
    assert endtime == 2000
    assert path.read_bytes() == b"ccache"

    path.unlink()
    Cache.endtime = 1000
    with pytest.raises(RuntimeError, match="expired"):
        module.request_ticket(connection)
    assert not path.exists()


def test_module_result_reports_ticket_end_time(monkeypatch, tmp_path):
    module = delegation.NXCModule()
    module.user = "alice"
    module.spn = "cifs/web1.example.test"
    module.account = None
    path = tmp_path / "ticket.ccache"
    log = SimpleNamespace(highlight=lambda *args: None, success=lambda *args: None,
                          display=lambda *args: None, fail=lambda *args: None)
    monkeypatch.setattr(module, "read_delegations", lambda connection: ([], None))
    monkeypatch.setattr(module, "request_ticket", lambda connection: (path, 2000))
    result = module.on_login(SimpleNamespace(log=log), SimpleNamespace(host="10.0.0.10", username="svc"))
    assert result.status is ResultStatus.SUCCESS
    assert result.data.ccache == str(path)
    assert result.data.expires_at == 2000


def test_expired_cache_is_not_queued_or_connected(monkeypatch, tmp_path):
    module = playbook_module()
    cache = tmp_path / "ticket.ccache"
    cache.write_bytes(b"ccache")
    monkeypatch.setattr(module, "time", lambda: 1000)
    log = SimpleNamespace(good=lambda *args, **kwargs: None, warn=lambda *args, **kwargs: None)
    kb = module.KB(log, allowed={"10.0.0.10", "10.0.0.20"})
    expired = module.Cred("example.test", "alice", str(cache), "ccache", target_scope="10.0.0.20",
                          protocols=("smb",), kdc_host="10.0.0.10", expires_at=1000)
    assert not kb.add_cred(expired)
    future = module.Cred("example.test", "alice", str(cache), "ccache", target_scope="10.0.0.20",
                         protocols=("smb",), kdc_host="10.0.0.10", expires_at=2000)
    assert kb.add_cred(future)
    monkeypatch.setattr(module, "time", lambda: 2000)
    seen = []
    host = SimpleNamespace(target="10.0.0.20", smb=lambda **kwargs: seen.append(kwargs))
    assert module.open_session(kb, host, "smb", future) is None
    assert seen == []
