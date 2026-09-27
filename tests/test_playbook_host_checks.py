"""Offline host checks distinguish missing evidence from negative findings."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import nxc.modules.lockscreendoors as lock_code
import nxc.modules.ntlmv1 as ntlm_code
from nxc.helpers.registry import RegistryValue
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("value", [RegistryValue(), RegistryValue(True, 0, 4), RegistryValue(True, 5, 4), RegistryValue(error="denied")])
def test_ntlm_setting_is_an_observation(monkeypatch, value):
    monkeypatch.setattr(ntlm_code, "read_registry_value", Mock(return_value=value))
    result = ntlm_code.NXCModule().on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(host="offline.invalid"))
    assert result.data.registry == value
    assert result.status is (ResultStatus.FAILED if value.error else ResultStatus.SUCCESS if value.present else ResultStatus.NEGATIVE)


@pytest.mark.parametrize(("description", "error", "status"), [("Expected", None, ResultStatus.NEGATIVE), ("Windows Command Processor", None, ResultStatus.SUCCESS), (None, "invalid PE", ResultStatus.FAILED)])
def test_description_outcomes_preserve_unknown(monkeypatch, description, error, status):
    module = lock_code.NXCModule()
    module.expected_descriptions = {"one.exe": ["Expected"]}
    module.description_error = error
    monkeypatch.setattr(module, "get_description", Mock(return_value=description))
    context = SimpleNamespace(log=Mock())
    result = module.on_admin_login(context, SimpleNamespace(host="offline.invalid", conn=Mock()))
    assert result.status is status
    record = result.data.files[0]
    assert record["matches_expected"] is (None if error else description == "Expected")
    assert record["description"] == description
    if error:
        context.log.display.assert_not_called()


def test_failed_file_does_not_erase_prior_finding(monkeypatch):
    module = lock_code.NXCModule()
    module.expected_descriptions = {"one.exe": ["Expected"], "two.exe": ["Expected"]}
    module.description_error = None
    monkeypatch.setattr(module, "get_description", Mock(return_value="Unexpected"))
    conn = Mock()
    conn.getFile.side_effect = [None, RuntimeError("read denied")]
    result = module.on_admin_login(SimpleNamespace(log=Mock()), SimpleNamespace(host="offline.invalid", conn=conn))
    assert result.status is ResultStatus.FAILED
    assert result.data.files[0]["matches_expected"] is False
    assert result.data.files[1]["matches_expected"] is None


def test_bad_pe_returns_error_without_uninitialized_context():
    module = lock_code.NXCModule()
    assert module.get_description(b"not a PE file") is None
    assert module.description_error
