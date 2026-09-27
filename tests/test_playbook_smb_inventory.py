"""Offline SMB disk and local group inventory contracts."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus
from nxc.protocols.smb.samrfunc import SamrFunc


@pytest.mark.parametrize("failure", [None, "enumeration", "cleanup"])
def test_disks_preserve_records_and_close_rpc(monkeypatch, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    dce = Mock()
    monkeypatch.setattr(protocol, "NXCRPCConnection", Mock(return_value=Mock(connect=Mock(return_value=dce))))
    enum = Mock(return_value={"DiskInfoStruct": {"Buffer": [{"Disk": "C:\x00"}, {"Disk": "\x00"}]}})
    monkeypatch.setattr(protocol.srvs, "hNetrServerDiskEnum", enum)
    if failure == "enumeration":
        enum.side_effect = RuntimeError("enumeration failed")
    elif failure == "cleanup":
        dce.disconnect.side_effect = RuntimeError("cleanup failed")
    fake = SimpleNamespace(logger=Mock(), host="offline.invalid", playbook_mode=True)
    result = protocol.smb.disks(fake)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.disks == ([] if failure == "enumeration" else ["C:"])
    assert result.error == (f"{failure} failed" if failure else None)
    dce.disconnect.assert_called_once_with()


@pytest.mark.parametrize(("group", "errors", "cleanup"), [("", [], []), ("Administrators", [], []), ("Administrators", ["lookup failed"], []), ("", [], ["close failed"])])
def test_local_group_contract_preserves_identity_and_errors(monkeypatch, group, errors, cleanup):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    groups = {"Administrators": 544}
    members = {"S-1-5-21-1000": "Alice"} if group else {}
    query = Mock(errors=errors, get_local_groups=Mock(return_value=(groups, members)), close=Mock(return_value=cleanup))
    monkeypatch.setattr(protocol, "SamrFunc", Mock(return_value=query))
    fake = SimpleNamespace(logger=Mock(), host="offline.invalid", hostname="OFFLINE", playbook_mode=True, args=SimpleNamespace(local_groups=group), db=Mock())
    fake.db.add_group.return_value = [5]
    result = protocol.smb.local_groups(fake)
    assert result.data.groups == {"Administrators": 544}
    assert result.data.members == members
    assert result.data.members_queried is bool(group)
    assert result.status is (ResultStatus.FAILED if errors or cleanup else ResultStatus.SUCCESS)
    assert result.error == ("; ".join(errors + cleanup) or None)
    query.close.assert_called_once_with()
    if not group:
        fake.db.add_group.assert_called_once_with("OFFLINE", "Administrators", rid=544)


def test_group_lookup_keeps_builtin_result_when_custom_lookup_fails():
    fake = SimpleNamespace(logger=Mock(), errors=[], get_builtin_groups=Mock(return_value=({"Administrators": 544}, {"S-1-5-21-1000": "Alice"})), get_custom_groups=Mock(side_effect=RuntimeError("custom denied")))
    groups, members = SamrFunc.get_local_groups(fake, "Administrators")
    assert groups == {"Administrators": 544}
    assert members == {"S-1-5-21-1000": "Alice"}
    assert fake.errors == ["custom denied"]


def test_member_lookup_keeps_prior_members_on_error():
    fake = SimpleNamespace(logger=Mock(), errors=[], samr_query=Mock(), lsa_query=Mock())
    fake.samr_query.get_alias_members.side_effect = [["S-1-5-21-1000"], RuntimeError("members denied")]
    fake.lsa_query.lookup_sids.return_value = ["Alice"]
    members = SamrFunc.get_local_users(fake, {"First": 1, "Second": 2}, "domain")
    assert members == {"S-1-5-21-1000": "Alice"}
    assert fake.errors == ["members denied"]


def test_close_releases_both_rpc_connections_even_after_failure():
    samr, lsa = Mock(), Mock()
    samr.dce.disconnect.side_effect = RuntimeError("close denied")
    samr_disconnect, lsa_disconnect = samr.dce.disconnect, lsa.dce.disconnect
    fake = SimpleNamespace(samr_query=samr, lsa_query=lsa, logger=Mock())
    assert SamrFunc.close(fake) == ["close denied"]
    samr_disconnect.assert_called_once_with()
    lsa_disconnect.assert_called_once_with()
    assert SamrFunc.close(fake) == []


@pytest.mark.parametrize("action", ["disks", "local_groups"])
def test_empty_inventory_is_negative(monkeypatch, action):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    fake = SimpleNamespace(logger=Mock(), host="offline.invalid", playbook_mode=True, args=SimpleNamespace(local_groups=""))
    monkeypatch.setattr(protocol, "NXCRPCConnection", Mock(return_value=Mock(connect=Mock(return_value=Mock()))))
    monkeypatch.setattr(protocol.srvs, "hNetrServerDiskEnum", Mock(return_value={"DiskInfoStruct": {"Buffer": []}}))
    monkeypatch.setattr(protocol, "SamrFunc", Mock(return_value=Mock(errors=[], get_local_groups=Mock(return_value=({}, {})), close=Mock(return_value=[]))))
    result = getattr(protocol.smb, action)(fake)
    assert result.status is ResultStatus.NEGATIVE
    assert result.error is None


def test_group_constructor_failure_is_failed_result(monkeypatch):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    monkeypatch.setattr(protocol, "SamrFunc", Mock(side_effect=RuntimeError("bind denied")))
    fake = SimpleNamespace(logger=Mock(), host="offline.invalid", playbook_mode=True, args=SimpleNamespace(local_groups=""))
    result = protocol.smb.local_groups(fake)
    assert result.status is ResultStatus.FAILED
    assert result.error == "bind denied"
    assert result.data.groups == {}


def test_custom_group_members_use_current_domain_aliases():
    fake = SimpleNamespace(samr_query=Mock(), get_local_users=Mock())
    fake.samr_query.get_domains.return_value = ["Builtin", "FIRST", "SECOND"]
    fake.samr_query.get_domain_handle.side_effect = ["first-handle", "second-handle"]
    fake.samr_query.get_domain_aliases.side_effect = [{"First": 1}, {"Second": 2}]
    fake.get_local_users.side_effect = [{"S-1-5-21-1": "Alice"}, {"S-1-5-21-2": "Bob"}]
    groups, members = SamrFunc.get_custom_groups(fake, "selection")
    assert groups == {"First": 1, "Second": 2}
    assert members == {"S-1-5-21-1": "Alice", "S-1-5-21-2": "Bob"}
    assert fake.get_local_users.call_args_list[1].args == ({"Second": 2}, "second-handle")
