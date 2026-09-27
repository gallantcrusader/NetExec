"""Exercise CLI result saving and exit codes without network operations."""

import json
from unittest.mock import Mock

import pytest

from nxc.playbooks import runner


@pytest.mark.parametrize(("status", "expected_code", "expected_status"), [
    ("SUCCESS", 0, "success"),
    ("NEGATIVE", 0, "success"),
    ("SKIPPED", 0, "success"),
    ("FAILED", 1, "completed_with_errors"),
])
def test_cli_exit_code_reflects_continued_failures(tmp_path, status, expected_code, expected_status):
    script = tmp_path / "workflow.py"
    script.write_text(
        "from nxc.playbooks.results import ActionResult, ResultStatus\n"
        "from nxc.playbooks.runner import FailureData\n"
        "def run(host):\n"
        "    if host.target == '192.0.2.1':\n"
        f"        host.record(ActionResult('smb', 'offline', host.target, ResultStatus.{status}, FailureData('example')), stop_on_error=False)\n",
        encoding="utf-8",
    )
    output = tmp_path / "results.json"
    code = runner.main([str(script), "192.0.2.1", "192.0.2.2", "--results", str(output)])
    assert code == expected_code
    hosts = json.loads(output.read_text())["hosts"]
    assert [host["target"] for host in hosts] == ["192.0.2.1", "192.0.2.2"]
    assert [host["status"] for host in hosts] == [expected_status, "success"]


def test_invalid_writer_is_rejected_before_running_hosts(tmp_path, monkeypatch):
    script = tmp_path / "bad_writer.py"
    script.write_text("def run(host):\n    raise AssertionError('must not run')\nsave_results = 42\n", encoding="utf-8")
    run_host = Mock()
    monkeypatch.setattr(runner, "run_host", run_host)
    with pytest.raises(ValueError, match="save_results must be a function"):
        runner.main([str(script), "192.0.2.1", "--results", str(tmp_path / "results.json")])
    run_host.assert_not_called()


def test_one_host_exception_does_not_prevent_saving_other_hosts(tmp_path):
    script = tmp_path / "mixed.py"
    script.write_text("def run(host):\n    if host.target == '192.0.2.1':\n        raise RuntimeError('local failure')\n", encoding="utf-8")
    output = tmp_path / "results.json"
    assert runner.main([str(script), "192.0.2.1", "192.0.2.2", "--results", str(output)]) == 1
    hosts = json.loads(output.read_text())["hosts"]
    assert hosts[0]["error"] == "local failure"
    assert hosts[1]["status"] == "success"


@pytest.mark.parametrize("source", [
    "async def run(host):\n    pass\n",
    "def run(host):\n    yield 1\n",
    "def run():\n    pass\n",
    "def run(host):\n    pass\ndef save_results(runs):\n    pass\n",
    "def run(host):\n    pass\nasync def save_results(runs, path):\n    pass\n",
])
def test_invalid_callback_is_rejected_before_running_hosts(tmp_path, monkeypatch, source):
    script = tmp_path / "invalid_callback.py"
    script.write_text(source, encoding="utf-8")
    run_host = Mock()
    monkeypatch.setattr(runner, "run_host", run_host)
    with pytest.raises(ValueError, match="must"):
        runner.main([str(script), "192.0.2.1", "--results", str(tmp_path / "results.json")])
    run_host.assert_not_called()
