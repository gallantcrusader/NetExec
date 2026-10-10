"""Typed password-reset results without contacting a domain controller."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

from nxc.playbooks.results import ResultStatus


def test_change_password_only_stores_an_acknowledged_reset(monkeypatch):
    code = import_module("nxc.modules.change-password")
    module = code.NXCModule()
    db = Mock()
    db.get_user.side_effect = [[SimpleNamespace(_mapping={"id": 7})],
                               [SimpleNamespace(_mapping={"id": 8, "credtype": "plaintext",
                                                          "password": "replacement"})]]
    context = SimpleNamespace(protocol="smb", log=Mock(), db=db)
    module.options(context, {"USER": "target", "NEWPASS": "replacement"})
    rpc = Mock()
    monkeypatch.setattr(module, "authenticate", Mock(return_value=rpc))
    change = Mock()
    monkeypatch.setattr(module, "smb_samr_change", change)
    connection = SimpleNamespace(host="offline.invalid", domain="EXAMPLE", username="operator",
                                 password="old", nthash="")

    result = module.on_login(context, connection)
    assert result.status is ResultStatus.SUCCESS
    assert result.data.completed
    assert result.data.stored
    assert (result.data.username, result.data.domain, result.data.credential_kind,
            result.data.new_secret) == ("target", "EXAMPLE", "plaintext", "replacement")
    assert result.data.credential_id == 8
    change.assert_called_once_with(context, connection, "target", "", "replacement", "")
    db.remove_credentials.assert_called_once_with([7])
    db.add_credential.assert_called_once_with("plaintext", "EXAMPLE", "target", "replacement")
    rpc.disconnect.assert_called_once()


def test_change_password_failure_does_not_store_new_credential(monkeypatch):
    code = import_module("nxc.modules.change-password")
    module = code.NXCModule()
    db = Mock()
    context = SimpleNamespace(protocol="smb", log=Mock(), db=db)
    module.options(context, {"USER": "target", "NEWNTHASH": "a" * 32})
    rpc = Mock()
    monkeypatch.setattr(module, "authenticate", Mock(return_value=rpc))
    monkeypatch.setattr(module, "smb_samr_change", Mock(side_effect=RuntimeError("access denied")))
    connection = SimpleNamespace(host="offline.invalid", domain="EXAMPLE", username="operator",
                                 password="old", nthash="")

    result = module.on_login(context, connection)
    assert result.status is ResultStatus.FAILED
    assert not result.data.completed
    assert not result.data.stored
    assert "access denied" in result.error
    db.remove_credentials.assert_not_called()
    db.add_credential.assert_not_called()
    rpc.disconnect.assert_called_once()


def test_change_password_reports_database_write_without_matching_row(monkeypatch):
    code = import_module("nxc.modules.change-password")
    module = code.NXCModule()
    db = Mock()
    db.get_user.side_effect = [[], []]
    context = SimpleNamespace(protocol="smb", log=Mock(), db=db)
    module.options(context, {"USER": "target", "NEWPASS": "replacement"})
    monkeypatch.setattr(module, "authenticate", Mock(return_value=Mock()))
    monkeypatch.setattr(module, "smb_samr_change", Mock())
    connection = SimpleNamespace(host="offline.invalid", domain="EXAMPLE", username="operator",
                                 password="old", nthash="")

    result = module.on_login(context, connection)
    assert result.status is ResultStatus.FAILED
    assert result.data.completed
    assert not result.data.stored
    assert result.data.credential_id is None
    assert "not found in the NetExec database" in result.error
