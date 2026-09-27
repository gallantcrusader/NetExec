"""LAPS records preserve source, unavailable values, and partial decode failures."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.modules import laps
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.capture import RecordingLogger
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus
from nxc.playbooks import runner


def entry(name="BRAAVOS$", **attributes):
    row = SearchResultEntry()
    row["objectName"] = "CN=Braavos,DC=essos,DC=local"
    for index, (key, value) in enumerate({"sAMAccountName": name, "dNSHostName": "braavos.essos.local", "distinguishedName": str(row["objectName"]), **attributes}.items()):
        row["attributes"][index]["type"] = key
        row["attributes"][index]["vals"][0] = value
    return row


def run_module(rows, options=None, error=None):
    module = laps.NXCModule()
    context = SimpleNamespace(log=RecordingLogger(Mock()))
    module.options(context, options or {})
    connection = SimpleNamespace(host="192.0.2.12", search=Mock(return_value=rows), last_search_error=error, username="reader", password="secret", domain="essos.local", nthash="", kerberos=False, kdcHost=None, dns_server="192.0.2.12")
    result = module.on_login(context, connection)
    validate_module_result(module, result, "ldap", connection.host)
    return result, connection


def test_legacy_password_has_no_fabricated_account_name():
    result, connection = run_module([entry(**{"ms-MCS-AdmPwd": "Legacy!", "ms-MCS-AdmPwdExpirationTime": "1334567890"})], {"COMPUTER": "BRA*(x)\\z"})
    assert result.ok
    record = result.data.computers[0]
    assert record.computer == "BRAAVOS$"
    assert record.username is None
    assert record.password == "Legacy!"
    assert record.source == "ms-MCS-AdmPwd"
    assert record.attributes["ms-MCS-AdmPwdExpirationTime"] == "1334567890"
    assert r"(name=BRA*\28x\29\5cz)" in connection.search.call_args.args[0]


def test_windows_laps_payload_and_case_insensitive_attribute_names():
    result, _ = run_module([entry(**{"MSLAPS-PASSWORD": '{"n":"managed-admin","p":"New!","t":"abc"}', "ms-MCS-AdmPwd": "old"})])
    record = result.data.computers[0]
    assert record.username == "managed-admin"
    assert record.password == "New!"
    assert record.source == "msLAPS-Password"


def test_encrypted_bytes_preserved_and_decrypted(monkeypatch):
    extract = Mock(return_value=SimpleNamespace(run=lambda: '{"n":"admin","p":"Decrypted!"}'))
    monkeypatch.setattr(laps, "LAPSv2Extract", extract)
    result, _ = run_module([entry(**{"msLAPS-EncryptedPassword": b"ASCII-looking-binary", "msLAPS-Password": '{"n":"old","p":"old"}'})])
    assert result.ok
    record = result.data.computers[0]
    assert record.password == "Decrypted!"
    assert record.source == "msLAPS-EncryptedPassword"
    assert record.attributes["msLAPS-EncryptedPassword"] == b"ASCII-looking-binary"
    assert extract.call_args.args[0] == b"ASCII-looking-binary"


@pytest.mark.parametrize("payload", ["{invalid", "[]", '{"n":"admin"}', '{"n":"admin","p":42}', '{"n":"","p":"secret"}'])
def test_malformed_payload_retains_other_computers(payload):
    result, _ = run_module([entry("BAD$", **{"msLAPS-Password": payload}), entry("GOOD$", **{"ms-MCS-AdmPwd": "Good!"})])
    assert result.status is ResultStatus.FAILED
    assert result.data.computers[0].error
    assert result.data.computers[0].password is None
    assert result.data.computers[1].password == "Good!"


def test_encrypted_failure_never_substitutes_an_older_password(monkeypatch):
    monkeypatch.setattr(laps, "LAPSv2Extract", Mock(return_value=SimpleNamespace(run=lambda: None)))
    result, _ = run_module([entry(**{"msLAPS-EncryptedPassword": b"blob", "ms-MCS-AdmPwd": "Old!"})])
    assert result.status is ResultStatus.FAILED
    assert result.data.computers[0].password is None
    assert "could not be decrypted" in result.error


@pytest.mark.parametrize("rows", [[], [entry()]])
def test_unavailable_password_is_negative(rows):
    result, _ = run_module(rows)
    assert result.status is ResultStatus.NEGATIVE
    assert result.error is None


def test_ldap_error_retains_partial_password_evidence():
    result, _ = run_module([entry(**{"ms-MCS-AdmPwd": "Readable!"})], error="sizeLimitExceeded")
    assert result.status is ResultStatus.FAILED
    assert result.error == "sizeLimitExceeded"
    assert result.data.computers[0].password == "Readable!"


@pytest.mark.parametrize(("ready", "flag", "skip", "unknown", "expected"), [(True, True, False, False, True), (True, False, False, False, False), (True, True, True, False, None), (False, True, False, False, None), (True, False, False, True, None)])
def test_connection_exposes_protocol_admin_observation(monkeypatch, ready, flag, skip, unknown, expected):
    class OfflineProtocol:
        def __init__(self, args, db, target, defer_flow=False):
            self.host = target
            self.transport_open = True
            self.username = "user"
            self.admin_privs = flag
            if unknown:
                self.admin_check_result = None
                self.admin_check_error = "RPC timeout"

        def open_session(self, anonymous=False):
            return ready

        def close_session(self):
            pass

    host = runner.HostContext("192.0.2.23", [])
    host.protocols = {"smb": {"path": "protocol", "dbpath": "database"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(smb=OfflineProtocol) if path == "protocol" else SimpleNamespace(database=lambda engine: object()))
    monkeypatch.setattr(runner, "create_db_engine", lambda path: Mock())
    session = host.smb(no_admin_check=skip)
    assert session.result.data.admin_privileges is expected
    assert session.result.data.admin_check_error == ("RPC timeout" if unknown else None)
    host.close()


@pytest.mark.parametrize("stage", ["success", "denied", "transport", "enumeration", "skipped"])
def test_smb_admin_check_distinguishes_denial_and_errors_and_closes_rpc(monkeypatch, stage):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/smb.py")
    rpc = Mock()
    monkeypatch.setattr(protocol, "NXCRPCConnection", Mock(return_value=rpc))
    opened = Mock(return_value={"lpScHandle": "handle"})
    enumerated, closed = Mock(), Mock()
    monkeypatch.setattr(protocol.scmr, "hROpenSCManagerW", opened)
    monkeypatch.setattr(protocol.scmr, "hREnumServicesStatusW", enumerated)
    monkeypatch.setattr(protocol.scmr, "hRCloseServiceHandle", closed)
    if stage == "denied":
        opened.side_effect = protocol.scmr.DCERPCException(error_code=5)
    elif stage == "transport":
        rpc.connect.side_effect = RuntimeError("transport timeout")
    elif stage == "enumeration":
        enumerated.side_effect = RuntimeError("enumeration timeout")
    connection = SimpleNamespace(args=SimpleNamespace(no_admin_check=stage == "skipped"), host="192.0.2.23", logger=Mock(), admin_privs=True)
    protocol.smb.check_if_admin(connection)
    assert connection.admin_privs is (stage == "success")
    assert connection.admin_check_result is (True if stage == "success" else False if stage == "denied" else None)
    assert bool(connection.admin_check_error) is (stage in {"transport", "enumeration"})
    if stage == "skipped":
        rpc.connect.assert_not_called()
    else:
        rpc.disconnect.assert_called_once()
    if stage in {"success", "enumeration"}:
        closed.assert_called_once_with(rpc.connect.return_value, "handle")
    else:
        closed.assert_not_called()
