"""Offline JSON command outputs for KeePass discovery."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules.keepass_discover import NXCModule
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("mode", ["ALL", "PROCESS", "FILES"])
def test_discovery_records_and_queried_flags(mode):
    context = SimpleNamespace(log=Mock())
    module = NXCModule()
    module.options(context, {"SEARCH_TYPE": mode})
    process = {"Id": 12, "UserName": "EXAMPLE\\Alice", "ProcessName": "KeePass"}
    outputs = [json.dumps({"records": [process], "errors": []})] if mode == "PROCESS" else [json.dumps({"records": [r"C:\Users\Alice\file.kdbx"], "errors": []})] if mode == "FILES" else [json.dumps({"records": [process], "errors": []}), json.dumps({"records": [r"C:\Users\Alice\file.kdbx"], "errors": []})]
    conn = SimpleNamespace(host="offline.invalid", execute=Mock(side_effect=outputs))
    result = module.on_admin_login(context, conn)
    validate_module_result(module, result, "smb", conn.host)
    assert result.status is ResultStatus.SUCCESS
    assert result.data.processes_queried is (mode != "FILES")
    assert result.data.files_queried is (mode != "PROCESS")
    if mode != "FILES":
        assert result.data.processes == [process]
    if mode != "PROCESS":
        assert result.data.files == [r"C:\Users\Alice\file.kdbx"]


@pytest.mark.parametrize("output", [None, "", "Access denied", '{"records": 1, "errors": []}'])
def test_invalid_output_is_failure_not_empty_finding(output):
    module = NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"SEARCH_TYPE": "FILES"})
    result = module.on_admin_login(context, SimpleNamespace(host="offline.invalid", execute=Mock(return_value=output)))
    assert result.status is ResultStatus.FAILED
    assert result.data.outputs["files"] == output


def test_partial_file_scan_preserves_records():
    module = NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"SEARCH_TYPE": "FILES"})
    result = module.on_admin_login(context, SimpleNamespace(host="offline.invalid", execute=Mock(return_value=json.dumps({"records": ["file.kdbx"], "errors": ["directory denied"]}))))
    assert result.status is ResultStatus.FAILED
    assert result.data.files == ["file.kdbx"]
    assert "directory denied" in result.error
