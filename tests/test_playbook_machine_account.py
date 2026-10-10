"""Machine-account operations with fake LDAP and database interfaces."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldap import LDAPSessionError

from nxc.playbooks.results import ResultStatus


class FakeDatabase:
    def __init__(self, password=None):
        self.rows = [] if password is None else [{"id": 7, "domain": "example.test", "username": "BADPC$",
                                                  "credtype": "plaintext", "password": password}]

    def get_credentials(self, filter_term=None):
        return [SimpleNamespace(_mapping=row) for row in self.rows]

    def add_credential(self, kind, domain, username, password):
        self.rows.append({"id": 8, "domain": domain, "username": username,
                          "credtype": kind, "password": password})

    def remove_credentials(self, ids):
        self.rows = [row for row in self.rows if row["id"] not in ids]


@pytest.mark.parametrize("operation", ["add", "change_password", "delete"])
def test_ldap_machine_account_change_has_database_backed_result(operation):
    code = import_module("nxc.modules.add-computer")
    module = code.NXCModule()
    db = FakeDatabase(None if operation == "add" else "old")
    context = SimpleNamespace(protocol="ldap", log=Mock(), db=db)
    options = {"NAME": "BADPC"}
    if operation != "delete":
        options["PASSWORD"] = "new"
    if operation == "change_password":
        options["CHANGEPW"] = "True"
    if operation == "delete":
        options["DELETE"] = "True"
    module.options(context, options)
    ldap = Mock()
    connection = SimpleNamespace(host="offline.invalid", domain="example.test", baseDN="DC=example,DC=test",
                                 ldap_connection=ldap)

    result = module.on_login(context, connection)
    assert result.status is ResultStatus.SUCCESS
    assert result.data.operation == operation
    assert result.data.completed
    assert result.data.stored
    if operation == "add":
        ldap.add.assert_called_once()
    elif operation == "change_password":
        ldap.modify.assert_called_once()
    else:
        ldap.delete.assert_called_once_with("CN=BADPC,CN=Computers,DC=example,DC=test")
    if operation == "delete":
        assert result.data.credential_id is None
        assert db.rows == []
    else:
        assert result.data.credential_id == 8
        assert db.rows[0]["password"] == "new"


def test_failed_ldap_machine_creation_does_not_store_credential():
    code = import_module("nxc.modules.add-computer")
    module = code.NXCModule()
    db = FakeDatabase()
    context = SimpleNamespace(protocol="ldap", log=Mock(), db=db)
    module.options(context, {"NAME": "BADPC", "PASSWORD": "new"})
    ldap = Mock()
    ldap.add.side_effect = LDAPSessionError(errorString="entryAlreadyExists")
    connection = SimpleNamespace(host="offline.invalid", domain="example.test", baseDN="DC=example,DC=test",
                                 ldap_connection=ldap)

    result = module.on_login(context, connection)
    assert result.status is ResultStatus.FAILED
    assert not result.data.completed
    assert not result.data.stored
    assert db.rows == []


def test_samr_machine_creation_records_database_reference(monkeypatch):
    code = import_module("nxc.modules.add-computer")
    module = code.NXCModule()
    db = FakeDatabase()
    context = SimpleNamespace(protocol="smb", log=Mock(), db=db)
    module.options(context, {"NAME": "BADPC", "PASSWORD": "new"})
    rpc = Mock()
    rpc.request.return_value = {"UserHandle": "initial-user"}
    monkeypatch.setattr(code, "NXCRPCConnection", Mock(return_value=Mock(connect=Mock(return_value=rpc))))
    monkeypatch.setattr(code.samr, "hSamrConnect5", Mock(return_value={"ServerHandle": "server"}))
    monkeypatch.setattr(code.samr, "hSamrEnumerateDomainsInSamServer", Mock(return_value={
        "Buffer": {"Buffer": [{"Name": "EXAMPLE"}]}}))
    monkeypatch.setattr(code.samr, "hSamrLookupDomainInSamServer", Mock(return_value={"DomainId": "sid"}))
    monkeypatch.setattr(code.samr, "hSamrOpenDomain", Mock(return_value={"DomainHandle": "domain"}))
    not_found = code.samr.DCERPCSessionError(error_code=0xC0000073)
    monkeypatch.setattr(code.samr, "hSamrLookupNamesInDomain", Mock(side_effect=[
        not_found, {"RelativeIds": {"Element": [1001]}}]))
    monkeypatch.setattr(code.samr, "hSamrSetPasswordInternal4New", Mock())
    monkeypatch.setattr(code.samr, "hSamrOpenUser", Mock(return_value={"UserHandle": "trust-user"}))
    monkeypatch.setattr(code.samr, "hSamrSetInformationUser2", Mock())
    close = Mock()
    monkeypatch.setattr(code.samr, "hSamrCloseHandle", close)
    connection = SimpleNamespace(host="offline.invalid", domain="EXAMPLE", username="operator",
                                 conn=SimpleNamespace(getRemoteName=lambda: "DC1"))

    result = module.on_login(context, connection)
    assert result.status is ResultStatus.SUCCESS
    assert result.data.completed
    assert result.data.stored
    assert result.data.credential_id == 8
    assert db.rows[0]["username"] == "BADPC$"
    code.samr.hSamrSetPasswordInternal4New.assert_called_once_with(rpc, "initial-user", "new")
    assert [call.args[1] for call in close.call_args_list] == ["initial-user", "trust-user", "domain", "server"]
    rpc.disconnect.assert_called_once()
