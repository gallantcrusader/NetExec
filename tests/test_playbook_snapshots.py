"""Offline snapshot inventories preserve scope and cleanup errors."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ActionResult, ResultStatus


@pytest.mark.parametrize("failure", [None, "query", "cleanup", "empty"])
def test_smb_snapshot_inventory_disconnects_tree_only(failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    conn = Mock()
    conn.connectTree.return_value = 0
    conn.listSnapshots.return_value = [] if failure == "empty" else ["@GMT-2026.01.01-00.00.00"]
    if failure == "query":
        conn.listSnapshots.side_effect = RuntimeError("query denied")
    elif failure == "cleanup":
        conn.disconnectTree.side_effect = RuntimeError("cleanup denied")
    fake = SimpleNamespace(admin_privs=True, playbook_mode=True, host="offline.invalid", args=SimpleNamespace(list_snapshots="DATA"), conn=conn, logger=Mock())
    result = protocol.smb.list_snapshots(fake)
    assert result.status is (ResultStatus.FAILED if failure in ("query", "cleanup") else ResultStatus.NEGATIVE if failure == "empty" else ResultStatus.SUCCESS)
    assert result.data.share == "DATA"
    assert result.data.snapshots == ([] if failure in ("query", "empty") else ["@GMT-2026.01.01-00.00.00"])
    conn.disconnectTree.assert_called_once_with(0)
    conn.logoff.assert_not_called()
    conn.close.assert_not_called()


@pytest.mark.parametrize("error", [None, "partial query"])
def test_wmi_snapshot_result_keeps_actual_volume_property(error):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/wmi.py")
    data = protocol.WMIQueryData("query", "root\\cimv2", [{"VolumeName": {"value": "volume-guid"}, "ID": {"value": "snapshot-id"}}])
    original = ActionResult("wmi", "wmi_query", "offline.invalid", ResultStatus.FAILED if error else ResultStatus.SUCCESS, data, error=error)
    fake = SimpleNamespace(admin_privs=True, playbook_mode=True, args=SimpleNamespace(list_snapshots="ADMIN$"), logger=Mock(), query_result=Mock(return_value=original))
    result = protocol.wmi.list_snapshots(fake)
    assert result.action == "list_snapshots"
    assert result.error == error
    assert result.data is data
    assert original.action == "wmi_query"
    assert "VolumeName" in fake.query_result.call_args.args[0]
    assert "WHERE" not in fake.query_result.call_args.args[0]
