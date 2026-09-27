"""Offline command outcomes for remote connectivity checks."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules.test_connection import NXCModule
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("protocol", ["smb", "mssql"])
@pytest.mark.parametrize(("output", "reachable", "status"), [(["True\r\n"], True, ResultStatus.SUCCESS), ([b"False\r\n"], False, ResultStatus.NEGATIVE), ([], None, ResultStatus.FAILED), (["Access denied"], None, ResultStatus.FAILED), (None, None, ResultStatus.FAILED)])
def test_connectivity_result_distinguishes_command_failure(protocol, output, reachable, status):
    module = NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"HOST": "destination.invalid"})
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol=protocol), ps_execute=Mock(return_value=output))
    result = module.on_admin_login(context, conn)
    validate_module_result(module, result, protocol, conn.host)
    assert result.status is status
    assert result.data.reachable is reachable
    assert result.data.destination == "destination.invalid"
    assert bool(result.error) is (status is ResultStatus.FAILED)


def test_destination_is_a_literal_powershell_argument():
    module = NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"HOST": "host'; Write-Output 'text"})
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol="smb"), ps_execute=Mock(side_effect=RuntimeError("execution unavailable")))
    result = module.on_admin_login(context, conn)
    assert "-ComputerName 'host''; Write-Output ''text'" in conn.ps_execute.call_args.args[0]
    assert result.status is ResultStatus.FAILED
    assert result.error == "execution unavailable"
    assert result.data.reachable is None
