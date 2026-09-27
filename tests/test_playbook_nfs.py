"""Offline NFS share records and authentication restoration."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("failure", [False, True])
def test_nfs_shares_keep_values_and_restore_session(monkeypatch, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/nfs.py")
    client = Mock()
    client.fsstat.return_value = {"resok": {"fbytes": 40, "tbytes": 100}}
    client.getattr.return_value = {"attributes": {"uid": 1000}}
    client.access.side_effect = lambda handle, mask, auth: {"status": 5} if failure else {"status": 0, "resok": {"access": mask}}
    monkeypatch.setattr(protocol, "NFSv3", Mock(return_value=client))
    original = Mock()
    mount = Mock()
    mount.export.return_value = [SimpleNamespace(ex_dir=b"/public", ex_groups=[], ex_next=[])]
    mount.mnt.return_value = {"status": 0, "mountinfo": {"fhandle": b"handle"}}
    fake = SimpleNamespace(host="offline.invalid", port=111, args=SimpleNamespace(nfs_timeout=2), auth={"uid": 0, "gid": 0}, nfs3=original, portmap=Mock(), mount=mount, db=Mock(), logger=Mock(), playbook_mode=True, group_names=lambda groups: [])
    fake.export_records = lambda exports: protocol.nfs.export_records(fake, exports)
    fake.get_permissions = lambda handle: protocol.nfs.get_permissions(fake, handle)
    result = protocol.nfs.shares(fake)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.shares[0]["path"] == "/public"
    assert result.data.shares[0]["uid"] == 1000
    assert result.data.shares[0]["used_bytes"] == 60
    assert result.data.shares[0]["permissions"]["read"] is (None if failure else True)
    assert fake.auth == {"uid": 0, "gid": 0}
    assert fake.nfs3 is original
    mount.export.assert_called_once()
    mount.umnt.assert_called_once()
    client.disconnect.assert_called_once()
    original.disconnect.assert_not_called()


def test_access_mask_checks_bits_instead_of_object_identity():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/nfs.py")
    fake = SimpleNamespace(nfs3=Mock(), auth={}, playbook_mode=True)
    fake.nfs3.access.return_value = {"status": 0, "resok": {"access": 0xFFFF}}
    assert protocol.nfs.get_permissions(fake, b"handle") == (True, True, True)
    assert fake.last_permission_error is None


def test_export_nodes_preserve_quotes_unicode_and_group_association():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/nfs.py")
    group = SimpleNamespace(gr_name=b"192.0.2.0/24", gr_next=[SimpleNamespace(gr_name=b"2001:db8::/32", gr_next=[])])
    second = SimpleNamespace(ex_dir="/données".encode(), ex_groups=[], ex_next=[])
    first = SimpleNamespace(ex_dir=b"/team's files", ex_groups=[group], ex_next=[second])
    fake = SimpleNamespace()
    fake.group_names = lambda groups: protocol.nfs.group_names(fake, groups)
    assert protocol.nfs.export_records(fake, [first]) == [("/team's files", ["192.0.2.0/24", "2001:db8::/32"]), ("/données", ["Everyone"])]


def test_export_nodes_empty_list():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/nfs.py")
    assert protocol.nfs.export_records(SimpleNamespace(), []) == []


@pytest.mark.parametrize("failure", [False, True])
def test_recursive_enumeration_preserves_entries_and_restores_state(monkeypatch, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/nfs.py")
    client = Mock()
    monkeypatch.setattr(protocol, "NFSv3", Mock(return_value=client))
    original = Mock()
    mount = Mock()
    mount.mnt.return_value = {"status": 0, "mountinfo": {"fhandle": b"handle"}}
    fake = SimpleNamespace(host="offline.invalid", port=111, args=SimpleNamespace(nfs_timeout=2, enum_shares=None), auth={"uid": 0}, nfs3=original, portmap=Mock(), mount=mount, logger=Mock(), playbook_mode=True, export_records=lambda exports: [("/public", ["Everyone"])])
    entries = [{"path": "/public/file", "uid": 7, "read": True, "write": False, "execute": False, "filesize": "4 B"}]

    def listing(handle, share, depth):
        assert depth == 3
        fake.auth["uid"] = 7
        if failure:
            fake.listing_errors.append("partial listing")
        return entries

    fake.list_dir = listing
    result = protocol.nfs.enum_shares(fake)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.shares[0]["entries"] == entries
    assert fake.auth == {"uid": 0}
    assert fake.nfs3 is original
    mount.umnt.assert_called_once()
    client.disconnect.assert_called_once()
    entries.clear()
    assert len(result.data.shares[0]["entries"]) == 1
