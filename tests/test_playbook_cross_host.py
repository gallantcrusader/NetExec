"""Cross-host workflows retain scope, ordering, failure semantics, and cleanup."""

import json
from unittest.mock import Mock

import pytest

from nxc.playbooks import runner
from nxc.playbooks.results import ActionResult, ResultStatus


def result(target, status=ResultStatus.SUCCESS):
    return ActionResult("smb", "check", target, status, runner.FailureData("observed"), error="denied" if status is ResultStatus.FAILED else None)


def test_peer_cache_and_ordered_evidence_are_shared_but_sessions_are_per_host():
    root = runner.HostContext("192.0.2.1", ["-u", "alice"], {"domain": "example"}, ["192.0.2.2"])
    peer = root.at("192.0.2.2")
    assert root.at(root.target) is root
    assert peer.at(root.target) is root
    assert root.at(peer.target) is peer
    assert peer.connection_defaults == root.connection_defaults
    assert peer.shared_args == root.shared_args
    root.sessions["root"] = Mock()
    peer.sessions["peer"] = Mock()
    root.record(result(root.target))
    peer.record(result(peer.target))
    root.record(result(root.target))
    assert peer.run is root.run
    assert [r.target for r in root.run.results] == [root.target, peer.target, root.target]
    assert list(root.sessions) == ["root"]
    assert list(peer.sessions) == ["peer"]
    root.close()


def test_unlisted_peer_is_rejected_before_host_creation():
    root = runner.HostContext("192.0.2.1", [])
    with pytest.raises(ValueError, match=r"outside.*allowed targets"):
        root.at("192.0.2.2")
    assert list(root.workflow.hosts) == [root.target]


def test_scope_is_a_snapshot_and_peer_defaults_do_not_mutate_root():
    scope = ["192.0.2.2"]
    root = runner.HostContext("192.0.2.1", [], {"domain": "example"}, scope)
    scope.append("192.0.2.3")
    root.at("192.0.2.2").connection_defaults["domain"] = "other"
    assert root.connection_defaults["domain"] == "example"
    with pytest.raises(ValueError, match="outside"):
        root.at("192.0.2.3")


def test_default_stop_keeps_peer_failure_and_closes_every_session():
    opened = []

    def playbook(host):
        for context in (host, host.at("192.0.2.2")):
            session = Mock()
            opened.append(session)
            context.sessions["session"] = session
        host.at("192.0.2.2").record(result("192.0.2.2", ResultStatus.FAILED))
        raise AssertionError("failure should stop this workflow")

    run = runner.run_host("192.0.2.1", playbook, [], allowed_targets=["192.0.2.2"])
    assert run.error == "denied"
    assert run.results[0].target == "192.0.2.2"
    for session in opened:
        session.close.assert_called_once()


def test_cleanup_failure_does_not_leak_peer_sessions():
    root = runner.HostContext("192.0.2.1", [], allowed_targets=["192.0.2.2"])
    first, second = Mock(), Mock()
    first.close.side_effect = RuntimeError("close failed")
    root.sessions["a"] = first
    peer = root.at("192.0.2.2")
    peer.sessions["b"] = second
    with pytest.raises(RuntimeError, match="close failed"):
        root.close()
    second.close.assert_called_once()
    assert not root.sessions
    assert not peer.sessions
    root.close()
    second.close.assert_called_once()


def test_cli_extra_scope_does_not_start_extra_workflows_and_saves_partial_results(tmp_path):
    script = tmp_path / "cross_host.py"
    script.write_text(
        "from nxc.playbooks.results import ActionResult, ResultStatus\n"
        "from nxc.playbooks.runner import FailureData\n"
        "def run(host):\n"
        "    assert host.target == '192.0.2.1'\n"
        "    peer = host.at('192.0.2.2')\n"
        "    peer.record(ActionResult('smb', 'check', peer.target, ResultStatus.FAILED, FailureData('denied'), error='denied'), stop_on_error=False)\n"
        "    host.record(ActionResult('ldap', 'followup', host.target, ResultStatus.SUCCESS, FailureData('continued')))\n",
        encoding="utf-8",
    )
    output = tmp_path / "results.json"
    assert runner.main([str(script), "192.0.2.1", "--allow-target", "192.0.2.2", "--results", str(output)]) == 1
    hosts = json.loads(output.read_text())["hosts"]
    assert len(hosts) == 1
    assert hosts[0]["allowed_targets"] == ["192.0.2.1", "192.0.2.2"]
    assert hosts[0]["status"] == "completed_with_errors"
    assert [r["target"] for r in hosts[0]["results"]] == ["192.0.2.2", "192.0.2.1"]


def test_extra_targets_obey_exclusions_and_files(tmp_path):
    script = tmp_path / "scope.py"
    script.write_text("def run(host):\n    host.at('192.0.2.3')\n    host.at('192.0.2.2')\n", encoding="utf-8")
    scope = tmp_path / "scope.txt"
    scope.write_text("192.0.2.2\n192.0.2.3\n", encoding="utf-8")
    output = tmp_path / "results.json"
    assert runner.main([str(script), "192.0.2.1", "--allow-target", str(scope), "--exclude-hosts", "192.0.2.2", "--results", str(output)]) == 1
    run = json.loads(output.read_text())["hosts"][0]
    assert run["allowed_targets"] == ["192.0.2.1", "192.0.2.3"]
    assert "outside" in run["error"]


def test_root_workflows_do_not_share_sessions_or_results():
    first = runner.HostContext("192.0.2.1", [], allowed_targets=["192.0.2.2"])
    second = runner.HostContext("192.0.2.2", [], allowed_targets=["192.0.2.1"])
    assert first.at(second.target) is not second
    first.at(second.target).record(result(second.target))
    assert second.run.results == []


def test_custom_writer_receives_cross_host_results(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from nxc.playbooks.results import ActionResult, ResultStatus\n"
        "from nxc.playbooks.runner import FailureData\n"
        "def run(host):\n"
        "    peer = host.at('192.0.2.2')\n"
        "    peer.record(ActionResult('smb', 'check', peer.target, ResultStatus.SUCCESS, FailureData('observed')))\n"
        "def save_results(runs, path):\n"
        "    path.write_text(runs[0].results[0].target)\n",
        encoding="utf-8",
    )
    output = tmp_path / "result.txt"
    assert runner.main([str(script), "192.0.2.1", "--allow-target", "192.0.2.2", "--results", str(output)]) == 0
    assert output.read_text() == "192.0.2.2"
