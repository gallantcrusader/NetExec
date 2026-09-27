"""Shared result contract rejection and failed-step conversion."""

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from nxc.playbooks.contracts import ResultContractError, validate_action_result, validate_module_result
from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import ConnectionData, HostContext, ProtocolSession


@dataclass
class Data:
    value: int = 1


@pytest.mark.parametrize(("field", "value"), [
    ("status", "failed"), ("data", Data), ("inputs", []), ("events", ["message"]),
    ("artifacts", ["file.txt"]), ("error", ValueError("error")), ("target", "different.invalid"),
])
def test_actions_and_modules_reject_same_invalid_envelope(field, value):
    result = ActionResult("smb", "example", "offline.invalid", ResultStatus.SUCCESS, Data())
    setattr(result, field, value)
    module = SimpleNamespace(name="example", result_type=Data)
    with pytest.raises(ResultContractError):
        validate_action_result(result, "smb", "example", "offline.invalid")
    with pytest.raises(ResultContractError):
        validate_module_result(module, result, "smb", "offline.invalid")


def test_string_failure_status_is_recorded_as_failed_step():
    host = HostContext("offline.invalid", [])
    fake = SimpleNamespace(host=host.target, example=lambda: ActionResult("smb", "example", host.target, "failed", Data()))
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", fake, SimpleNamespace(example=None), None, None, connected)
    result = session.example(stop_on_error=False)
    assert result.status is ResultStatus.FAILED
    assert "invalid status" in result.error
    assert host.run.failed


def test_recursive_data_is_a_contract_error():
    data = Data()
    data.value = data
    result = ActionResult("smb", "example", "offline.invalid", ResultStatus.SUCCESS, data)
    with pytest.raises(ResultContractError, match="cannot be saved"):
        validate_action_result(result, "smb", "example", "offline.invalid")
