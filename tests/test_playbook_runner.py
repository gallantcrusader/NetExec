"""Offline tests for per-host playbook dispatch and action results."""

from argparse import Namespace
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest

from nxc.cli import gen_cli_args
from nxc.connection import connection, requires_admin
from nxc.database import create_db_engine
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.protocols.smb import samruser
from nxc.playbooks.results import ActionResult, CredentialRef, ResultStatus
from nxc.playbooks.runner import ConnectionData, HostContext, PlaybookStepError, ProtocolSession, format_module_option, load_playbook, run_host
import nxc.playbooks.runner as playbook_runner


@dataclass
class SharesData:
    names: list[str]


class FakeConnection:
    host = "offline.invalid"

    def shares(self):
        return ActionResult("smb", "shares", self.host, ResultStatus.SUCCESS, SharesData(["Public"]), inputs={"effective_filter": "READ"})


class FakeEngine:
    def dispose(self):
        pass


def test_action_records_typed_result_without_a_network_connection():
    host = HostContext("offline.invalid", [])
    connection = FakeConnection()
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", connection, Namespace(shares=None, exclude_shares=None), None, FakeEngine(), connected)

    result = session.shares(exclude_shares=["IPC$"])

    assert result.data.names == ["Public"]
    assert result.inputs == {"effective_filter": "READ", "exclude_shares": ["IPC$"]}
    assert host.run.results == [result]


def test_typed_action_keeps_its_output_events():
    class VerboseConnection(FakeConnection):
        def __init__(self):
            self.logger = SimpleNamespace(highlight=lambda message: None)
            self.password = "secret"

        def shares(self):
            self.logger.highlight("Public share secret")
            return super().shares()

    host = HostContext("offline.invalid", [])
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", VerboseConnection(), Namespace(shares=None), None, FakeEngine(), connected)

    result = session.shares()

    assert result.data.names == ["Public"]
    assert result.events[0].message == "Public share secret"
    assert result.to_dict()["events"] == [{"level": "highlight", "message": "Public share secret"}]


def test_legacy_action_captures_messages_and_return_value():
    class LegacyConnection:
        host = "offline.invalid"

        def __init__(self):
            self.logger = SimpleNamespace(display=lambda message: None)

        def groups(self):
            self.logger.display("Found group")
            return ["Admins"]

    host = HostContext("offline.invalid", [])
    connection = LegacyConnection()
    original_logger = connection.logger
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", connection, Namespace(groups=True), None, FakeEngine(), connected)

    result = session.groups()

    assert result.ok
    assert result.kind == "captured"
    assert result.data.return_value == ["Admins"]
    assert result.to_dict()["data"]["events"] == [{"level": "display", "message": "Found group"}]
    assert connection.logger is original_logger


def test_action_validation_failure_is_recorded():
    host = HostContext("offline.invalid", [])
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", FakeConnection(), Namespace(shares=None), None, FakeEngine(), connected)

    result = session.action("shares", stop_on_error=False, unsupported=True)

    assert result.status is ResultStatus.FAILED
    assert "Unknown smb option" in result.error
    assert result.inputs == {"unsupported": True}


def test_action_exception_preserves_original_error():
    class BrokenAction:
        host = "offline.invalid"
        password = "secret"

        def shares(self):
            raise ValueError("secret rejected")

    host = HostContext("offline.invalid", [])
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", BrokenAction(), Namespace(shares=None), None, FakeEngine(), connected)

    result = session.shares(stop_on_error=False)

    assert result.error == "secret rejected"


def test_action_after_failed_connection_is_recorded():
    host = HostContext("offline.invalid", [])
    disconnected = ActionResult("smb", "connect", host.target, ResultStatus.NEGATIVE, ConnectionData(False, False, True))
    session = ProtocolSession(host, "smb", FakeConnection(), Namespace(shares=None), None, FakeEngine(), disconnected)

    result = session.shares(stop_on_error=False)

    assert result.status is ResultStatus.FAILED
    assert "No open smb session" in result.error


def test_admin_only_action_is_skipped_without_privileges():
    class AdminConnection:
        host = "offline.invalid"
        admin_privs = False
        called = False

        @requires_admin
        def wmi_query(self):
            self.called = True

    host = HostContext("offline.invalid", [])
    connection = AdminConnection()
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", connection, Namespace(wmi_query="SELECT *", exec_method="wmiexec"), None, FakeEngine(), connected)

    result = session.wmi_query()

    assert result.status is ResultStatus.SKIPPED
    assert connection.called is False


def test_failure_can_continue_on_one_host():
    host = HostContext("offline.invalid", [])
    failed = ActionResult("smb", "shares", host.target, ResultStatus.FAILED, SharesData([]), error="access denied")

    assert host.record(failed, stop_on_error=False) is failed
    assert host.run.to_dict()["status"] == "completed_with_errors"
    with pytest.raises(PlaybookStepError, match="access denied"):
        host.record(failed)


def test_noop_playbook_dispatches_without_a_network_connection():
    run = run_host("offline.invalid", lambda host: None, [])

    assert run.target == "offline.invalid"
    assert run.to_dict()["status"] == "success"


def test_module_options_preserve_false_and_lists():
    assert format_module_option(False) == "false"
    assert format_module_option(True) == "true"
    assert format_module_option(["pdf", "txt"]) == "pdf,txt"


def test_unknown_module_is_recorded_as_failed_step():
    host = HostContext("offline.invalid", [])
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", SimpleNamespace(host=host.target), Namespace(module=[], module_options=[]), None, FakeEngine(), connected)

    result = session.module("missing_playbook_module", stop_on_error=False, sample=True)

    assert result.status is ResultStatus.FAILED
    assert result.inputs == {"sample": True}
    assert "Unknown module" in result.error
    assert host.run.results == result.results


def test_credential_resolution_failure_is_recorded_before_connection(monkeypatch):
    host = HostContext("offline.invalid", [])

    def fail_credential(args, credential):
        raise ValueError("credential is unavailable")

    monkeypatch.setattr(host, "apply_credential", fail_credential)
    session = host.smb(credential=CredentialRef("smb", 99), stop_on_error=False)

    assert session.result.status is ResultStatus.FAILED
    assert session.result.error == "credential is unavailable"
    assert host.run.results == [session.result]


def test_playbook_can_define_its_own_dataclass():
    with TemporaryDirectory() as folder:
        path = Path(folder) / "workflow.py"
        path.write_text("from dataclasses import dataclass\n@dataclass\nclass Choice:\n    enabled: bool\ndef run(host):\n    assert Choice(True).enabled\n", encoding="utf-8")

        run = run_host("offline.invalid", load_playbook(path), [])

        assert run.error is None


def test_playbook_can_save_results_in_its_own_format():
    with TemporaryDirectory() as folder:
        path = Path(folder) / "workflow.py"
        output = Path(folder) / "results.txt"
        path.write_text(
            "def run(host):\n    pass\n"
            "def save_results(runs, path):\n    path.write_text(runs[0].target, encoding='utf-8')\n",
            encoding="utf-8",
        )

        code = playbook_runner.main(["offline.invalid", str(path), "--results", str(output)])

        assert code == 0
        assert output.read_text(encoding="utf-8") == "offline.invalid"


def test_successful_login_uses_exact_stored_credential_row():
    rows = [
        SimpleNamespace(id=3, domain="EXAMPLE", username="alex", password="old", credtype="plaintext"),
        SimpleNamespace(id=7, domain="EXAMPLE", username="alex", password="current", credtype="plaintext"),
    ]
    db = SimpleNamespace(get_credentials=lambda filter_term: rows)
    connection = SimpleNamespace(username="alex", domain="EXAMPLE", password="current", hash=None)

    assert HostContext.find_stored_credential("smb", db, connection) == CredentialRef("smb", 7)
    connection.password = "missing"
    assert HostContext.find_stored_credential("smb", db, connection) is None


def test_hash_login_uses_hash_row_without_secret_in_reference():
    rows = [SimpleNamespace(id=9, domain="EXAMPLE", username="alex", password="ab" * 16, credtype="hash")]
    db = SimpleNamespace(get_credentials=lambda filter_term: rows)
    connection = SimpleNamespace(username="alex", domain="EXAMPLE", password="", hash="ab" * 16)

    assert HostContext.find_stored_credential("ldap", db, connection) == CredentialRef("ldap", 9)


def test_successful_credential_type_wins_over_stale_connection_fields():
    rows = [
        SimpleNamespace(id=3, domain="EXAMPLE", username="alex", password="old", credtype="plaintext"),
        SimpleNamespace(id=9, domain="EXAMPLE", username="alex", password="ab" * 16, credtype="hash"),
    ]
    db = SimpleNamespace(get_credentials=lambda filter_term: rows)
    connection = SimpleNamespace(username="alex", domain="EXAMPLE", password="old", hash="ab" * 16, aesKey=None, authenticated_credential_type="hash")

    assert HostContext.find_stored_credential("ldap", db, connection) == CredentialRef("ldap", 9)


@pytest.mark.parametrize("stored_hash", ["aa:bb", "bb"])
def test_credential_reference_accepts_full_or_nt_only_hash(stored_hash):
    row = SimpleNamespace(id=11, domain="EXAMPLE", username="alex", password=stored_hash, credtype="hash")
    db = SimpleNamespace(get_credentials=lambda filter_term: [row])
    connection = SimpleNamespace(username="alex", domain="EXAMPLE", password="stale", hash=None, authenticated_credential_type="hash", authenticated_secret="aa:bb")

    assert HostContext.find_stored_credential("smb", db, connection) == CredentialRef("smb", 11)


def test_vnc_password_is_stored_once_and_can_be_referenced():
    with TemporaryDirectory() as folder:
        loader = ProtocolLoader()
        db_class = loader.load_protocol(loader.get_protocols()["vnc"]["dbpath"]).database
        engine = create_db_engine(str(Path(folder) / "vnc.db"))
        db_class.db_schema(engine)
        db = db_class(engine)
        credential_id = db.add_credential("", "password")

        assert db.add_credential("", "password") == credential_id
        assert HostContext.find_stored_credential("vnc", db, SimpleNamespace(username="", password="password", hash=None, domain=None)) == CredentialRef("vnc", credential_id)
        assert HostContext.find_stored_credential("vnc", db, SimpleNamespace(username="", password="", hash=None, domain=None)) is None
        assert connection.query_db_creds(SimpleNamespace(args=Namespace(cred_id=[str(credential_id)]), db=db, logger=SimpleNamespace(error=lambda message: None)))[:5] == ([None], [""], [False], ["password"], ["plaintext"])
        engine.dispose()


def test_existing_rdp_database_gains_credential_storage():
    with TemporaryDirectory() as folder:
        loader = ProtocolLoader()
        db_class = loader.load_protocol(loader.get_protocols()["rdp"]["dbpath"]).database
        engine = create_db_engine(str(Path(folder) / "rdp.db"))
        db_class.Host.__table__.create(engine)
        db = db_class(engine)

        credential_id = db.add_credential("hash", "EXAMPLE", "alex", "ab" * 16)

        assert db.add_credential("hash", "EXAMPLE", "alex", "ab" * 16) == credential_id
        assert db.get_credentials(filter_term=credential_id)[0].username == "alex"
        assert HostContext.find_stored_credential("rdp", db, SimpleNamespace(username="alex", password="", hash="ab" * 16, aesKey=None, domain="EXAMPLE")) == CredentialRef("rdp", credential_id)
        assert connection.query_db_creds(SimpleNamespace(args=Namespace(cred_id=[str(credential_id)]), db=db, logger=SimpleNamespace(error=lambda message: None)))[:5] == (["EXAMPLE"], ["alex"], [False], ["ab" * 16], ["hash"])
        engine.dispose()


def test_rdp_database_reference_populates_ldap_arguments(monkeypatch):
    with TemporaryDirectory() as folder:
        workspace = Path(folder) / "default"
        workspace.mkdir()
        monkeypatch.setattr(playbook_runner, "WORKSPACE_DIR", folder)
        monkeypatch.setattr(playbook_runner, "nxc_workspace", "default")
        loader = ProtocolLoader()
        db_class = loader.load_protocol(loader.get_protocols()["rdp"]["dbpath"]).database
        engine = create_db_engine(str(workspace / "rdp.db"))
        db = db_class(engine)
        hash_id = db.add_credential("hash", "EXAMPLE", "alex", "ab" * 16)
        aes_id = db.add_credential("aesKey", "EXAMPLE", "alex", "cd" * 16)
        engine.dispose()
        host = HostContext("offline.invalid", [])

        hash_args, _ = gen_cli_args(["ldap", "offline.invalid"])
        host.apply_credential(hash_args, CredentialRef("rdp", hash_id))
        aes_args, _ = gen_cli_args(["ldap", "offline.invalid"])
        host.apply_credential(aes_args, CredentialRef("rdp", aes_id))

        assert hash_args.username == ["alex"]
        assert hash_args.hash == ["ab" * 16]
        assert aes_args.aesKey == ["cd" * 16]
        assert aes_args.kerberos is True


def test_database_credential_lookup_preserves_ssh_key_data():
    row = SimpleNamespace(id=4, username="alex", password="passphrase", credtype="key")
    db = SimpleNamespace(get_credentials=lambda filter_term=None: [row], get_keys=lambda cred_id: [SimpleNamespace(data="PRIVATE KEY")])
    fake = SimpleNamespace(args=Namespace(cred_id=["4"]), db=db, logger=SimpleNamespace(error=lambda message: None))

    domains, usernames, owned, secrets, cred_types, data = connection.query_db_creds(fake)

    assert (domains, usernames, owned, secrets, cred_types, data) == ([None], ["alex"], [False], ["passphrase"], ["key"], ["PRIVATE KEY"])


def test_connect_error_is_saved_as_structured_failure(monkeypatch):
    class BrokenProtocol:
        attempts = 0

        def __init__(self, args, db, target, defer_flow=False):
            self.host = target

        def open_session(self, anonymous=False):
            type(self).attempts += 1
            raise RuntimeError("offline failure")

        def close_session(self):
            pass

    host = HostContext("offline.invalid", [])
    host.protocols = {"smb": {"path": "protocol", "dbpath": "database"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(smb=BrokenProtocol) if path == "protocol" else SimpleNamespace(database=lambda engine: object()))
    monkeypatch.setattr(playbook_runner, "create_db_engine", lambda path: FakeEngine())

    session = host.smb(stop_on_error=False)

    assert session.result.status is ResultStatus.FAILED
    assert session.result.data.message == "offline failure"
    assert host.run.to_dict()["results"][0]["action"] == "connect"
    host.smb(stop_on_error=False)
    assert BrokenProtocol.attempts == 2


def test_connection_probe_messages_are_recorded_without_network(monkeypatch):
    class OfflineProtocol(connection):
        def proto_logger(self):
            self.logger = SimpleNamespace(fail=lambda message: None)

        def create_conn_obj(self):
            self.logger.fail("transport unavailable")
            return False

    host = HostContext("127.0.0.1", [])
    host.protocols = {"ftp": {"path": "protocol", "dbpath": "database"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(ftp=OfflineProtocol) if path == "protocol" else SimpleNamespace(database=lambda engine: object()))
    monkeypatch.setattr(playbook_runner, "create_db_engine", lambda path: FakeEngine())

    session = host.ftp(stop_on_error=False)

    assert session.result.status is ResultStatus.NEGATIVE
    assert session.result.to_dict()["events"][-1] == {"level": "fail", "message": "transport unavailable"}
    assert session.result.events[0].level == "debug"


def test_anonymous_session_remains_open_after_named_session_is_created(monkeypatch):
    class ReusableProtocol:
        def __init__(self, args, db, target, defer_flow=False):
            self.host = target
            self.transport_open = True
            self.username = ""
            self.password = ""
            self.is_guest = False
            self.closed = False

        def open_session(self, anonymous=False):
            return True

        def close_session(self):
            self.closed = True

    host = HostContext("offline.invalid", [])
    host.protocols = {"smb": {"path": "protocol", "dbpath": "database"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(smb=ReusableProtocol) if path == "protocol" else SimpleNamespace(database=lambda engine: object()))
    monkeypatch.setattr(playbook_runner, "create_db_engine", lambda path: FakeEngine())

    anonymous = host.smb(anonymous=True)
    named = host.smb()

    assert anonymous.connection is not named.connection
    assert anonymous.connection.closed is False
    assert host.smb(anonymous=True) is anonymous
    host.close()
    assert anonymous.connection.closed is True
    assert named.connection.closed is True


def test_connection_options_create_distinct_reusable_sessions(monkeypatch):
    class ConfiguredProtocol:
        def __init__(self, args, db, target, defer_flow=False):
            self.args = args
            self.host = target
            self.transport_open = True
            self.username = args.username[0]
            self.password = args.password[0]
            self.is_guest = False

        def open_session(self, anonymous=False):
            return True

        def close_session(self):
            pass

    host = HostContext("offline.invalid", [])
    host.protocols = {"ldap": {"path": "protocol", "dbpath": "database"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(ldap=ConfiguredProtocol) if path == "protocol" else SimpleNamespace(database=lambda engine: object()))
    monkeypatch.setattr(playbook_runner, "create_db_engine", lambda path: FakeEngine())

    first = host.ldap(port=389, username="alex", password="secret")
    second = host.ldap(port=636, username="alex", password="secret")

    assert first is not second
    assert host.ldap(port=636, username="alex", password="secret") is second
    assert first.args.port == 389
    assert second.args.port == 636
    assert second.args.username == ["alex"]
    assert second.args.password == ["secret"]
    assert second.result.inputs["port"] == 636
    assert second.result.inputs["password"] == "secret"
    host.close()


def test_unknown_connection_option_is_recorded(monkeypatch):
    host = HostContext("offline.invalid", [])
    monkeypatch.setattr(playbook_runner, "create_db_engine", lambda path: raise_unexpected_engine_creation())

    session = host.smb(unknown_connection_flag=True, stop_on_error=False)

    assert session.result.status is ResultStatus.FAILED
    assert "Unknown smb connection option" in session.result.error


def raise_unexpected_engine_creation():
    raise AssertionError("Engine should not be created for an invalid option")


def test_guest_login_does_not_claim_a_stored_credential(monkeypatch):
    class GuestProtocol:
        def __init__(self, args, db, target, defer_flow=False):
            self.host = target
            self.transport_open = True
            self.username = "alex"
            self.password = "current"
            self.hash = None
            self.domain = "EXAMPLE"
            self.is_guest = True

        def open_session(self, anonymous=False):
            return True

        def close_session(self):
            pass

    row = SimpleNamespace(id=7, domain="EXAMPLE", username="alex", password="current", credtype="plaintext")
    host = HostContext("offline.invalid", [])
    host.protocols = {"smb": {"path": "protocol", "dbpath": "database"}}
    monkeypatch.setattr(host.loader, "load_protocol", lambda path: SimpleNamespace(smb=GuestProtocol) if path == "protocol" else SimpleNamespace(database=lambda engine: SimpleNamespace(get_credentials=lambda filter_term: [row])))
    monkeypatch.setattr(playbook_runner, "create_db_engine", lambda path: FakeEngine())

    session = host.smb()

    assert session.result.data.guest is True
    assert session.result.data.authenticated is False
    assert session.result.data.credential is None
    host.close()


def test_smb_user_enumeration_failure_is_not_reported_as_success(monkeypatch):
    class FailedDump:
        user_records = []
        exported = False
        error = "SAMR unavailable"

        def __init__(self, connection):
            pass

        def dump(self, requested_users=None, dump_path=None):
            return []

    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["smb"]["path"])
    monkeypatch.setattr(module, "UserSamrDump", FailedDump)
    fake = SimpleNamespace(args=SimpleNamespace(users=[], users_export=None), playbook_mode=True, host="offline.invalid")

    result = module.smb.users(fake)

    assert result.status is ResultStatus.FAILED
    assert result.error == "SAMR unavailable"
    assert result.artifacts == []


def test_samr_connection_error_is_retained_for_result(monkeypatch):
    class FailedRpc:
        def __init__(self, connection):
            pass

        def connect(self, *args):
            raise RuntimeError("SAMR unavailable")

    monkeypatch.setattr(samruser, "NXCRPCConnection", FailedRpc)
    dump = samruser.UserSamrDump(SimpleNamespace(logger=SimpleNamespace(debug=lambda message: None)))

    assert dump.dump() == []
    assert dump.error == "SAMR unavailable"


def test_smb_password_policy_error_stops_a_host(monkeypatch):
    class FailedDump:
        error = "SAMR access denied"

        def __init__(self, connection):
            pass

        def dump(self):
            return {}

    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["smb"]["path"])
    monkeypatch.setattr(module, "PassPolDump", FailedDump)

    result = module.smb.pass_pol(SimpleNamespace(playbook_mode=True, host="offline.invalid"))

    assert result.status is ResultStatus.FAILED
    assert result.error == "SAMR access denied"


@pytest.mark.parametrize(("user_filter", "expected"), [(None, ["alex", "sam"]), ("alex", ["alex"]), ("missing", [])])
def test_loggedon_users_returns_filtered_deduplicated_records(monkeypatch, user_filter, expected):
    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["smb"]["path"])
    monkeypatch.setattr(module, "NXCRPCConnection", lambda conn: SimpleNamespace(connect=lambda *args: object()))
    rows = [
        {"wkui1_logon_domain": "EXAMPLE\0", "wkui1_username": name + "\0", "wkui1_logon_server": "DC01\0"}
        for name in ["alex", "alex", "sam"]
    ]
    monkeypatch.setattr(module.wkst, "hNetrWkstaUserEnum", lambda *args: {"UserInfo": {"WkstaUserInfo": {"Level1": {"Buffer": rows}}}})
    fake = SimpleNamespace(
        host="offline.invalid", playbook_mode=True,
        args=Namespace(loggedon_users_filter=None, loggedon_users=user_filter),
        logger=SimpleNamespace(highlight=lambda message: None),
    )

    result = module.smb.loggedon_users(fake)

    assert [user.username for user in result.data.users] == expected
    assert all(user.domain == "EXAMPLE" and user.logon_server == "DC01" for user in result.data.users)
    assert result.status is (ResultStatus.SUCCESS if expected else ResultStatus.NEGATIVE)


def test_loggedon_users_keeps_rpc_failure_distinct_from_empty_result(monkeypatch):
    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["smb"]["path"])

    def fail_rpc(conn):
        raise RuntimeError("RPC unavailable")

    monkeypatch.setattr(module, "NXCRPCConnection", fail_rpc)
    fake = SimpleNamespace(
        host="offline.invalid", playbook_mode=True,
        args=Namespace(loggedon_users_filter=None, loggedon_users=None),
        logger=SimpleNamespace(fail=lambda message: None),
    )

    result = module.smb.loggedon_users(fake)

    assert result.status is ResultStatus.FAILED
    assert result.error == "RPC unavailable"


def test_module_records_all_hook_results_before_stopping(monkeypatch):
    with TemporaryDirectory() as folder:
        module_path = Path(folder) / "modules" / "dual.py"
        module_path.parent.mkdir()
        module_path.write_text("", encoding="utf-8")
        monkeypatch.setattr(playbook_runner, "NXC_PATH", folder)
        monkeypatch.setattr(playbook_runner.ModuleLoader, "init_module", lambda self, path: SimpleNamespace(name="dual"))
        host = HostContext("offline.invalid", [])
        args = Namespace(module=[], module_options=[])
        fake = SimpleNamespace(host="offline.invalid", action_results=[], modules=[])

        def call_modules():
            fake.action_results.extend([
                ActionResult("smb", "dual", fake.host, ResultStatus.FAILED, SharesData([]), error="first hook failed"),
                ActionResult("smb", "dual", fake.host, ResultStatus.SUCCESS, SharesData(["second hook ran"])),
            ])

        fake.call_modules = call_modules
        connected = ActionResult("smb", "connect", fake.host, ResultStatus.SUCCESS, ConnectionData(True, True, False))
        session = ProtocolSession(host, "smb", fake, args, None, FakeEngine(), connected)

        with pytest.raises(PlaybookStepError, match="first hook failed"):
            session.module("dual")

        assert len(host.run.results) == 2
        assert host.run.results[1].data.names == ["second hook ran"]


@pytest.mark.parametrize(("action", "rows"), [("computers", [{"sAMAccountName": "WS01$"}]), ("groups", [{"cn": "Team", "member": "CN=Alex", "description": "Example"}])])
def test_ldap_enumerations_return_records(monkeypatch, action, rows):
    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["ldap"]["path"])
    monkeypatch.setattr(module, "parse_result_attributes", lambda response: response)
    fake = SimpleNamespace(
        host="offline.invalid", playbook_mode=True, last_search_error=None,
        args=Namespace(groups=None), search=lambda *args: rows,
        logger=SimpleNamespace(debug=lambda *args, **kwargs: None, display=lambda message: None, highlight=lambda message: None),
    )

    result = getattr(module.ldap, action)(fake)

    assert result.status is ResultStatus.SUCCESS
    if action == "computers":
        assert result.data.computers == ["WS01$"]
    else:
        assert result.data.groups[0]["cn"] == "Team"
        assert result.data.members == []


@pytest.mark.parametrize(("action", "error"), [(action, error) for action in ("groups", "computers") for error in (None, "LDAP unavailable")])
def test_ldap_enumeration_empty_and_failure_are_distinct(monkeypatch, action, error):
    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["ldap"]["path"])
    monkeypatch.setattr(module, "parse_result_attributes", lambda response: response)
    fake = SimpleNamespace(
        host="offline.invalid", playbook_mode=True, last_search_error=error,
        args=Namespace(groups=None), search=lambda *args: [],
        logger=SimpleNamespace(debug=lambda message: None, highlight=lambda message: None),
    )

    result = getattr(module.ldap, action)(fake)

    assert result.status is (ResultStatus.FAILED if error else ResultStatus.NEGATIVE)
    assert result.error == error


def test_ldap_group_member_resolution_keeps_earlier_search_error(monkeypatch):
    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["ldap"]["path"])
    monkeypatch.setattr(module, "parse_result_attributes", lambda response: response)
    responses = iter([
        ([{"distinguishedName": "CN=Team", "objectSid": "S-1-5-21-100", "member": ["CN=Alex"]}], None),
        ([], "member search failed"),
        ([{"distinguishedName": "CN=Alex", "sAMAccountName": "alex"}], None),
    ])
    fake = SimpleNamespace(
        host="offline.invalid", playbook_mode=True, last_search_error=None, args=Namespace(groups="Team"),
        logger=SimpleNamespace(debug=lambda message: None, highlight=lambda message: None),
    )

    fake.scope = None

    def search(*args, **kwargs):
        rows, fake.last_search_error = next(responses)
        return rows

    fake.search = search
    result = module.ldap.groups(fake)

    assert result.status is ResultStatus.FAILED
    assert result.error == "member search failed"
    assert result.data.members[0]["sAMAccountName"] == "alex"


@pytest.mark.parametrize(("requested", "responses", "expected"), [
    (None, [([{"ou": "Team", "distinguishedName": "OU=Team"}], None)], ResultStatus.SUCCESS),
    ("Team", [([], None)], ResultStatus.NEGATIVE),
    ("Team", [([], "OU lookup failed")], ResultStatus.FAILED),
    ("Team", [([{"distinguishedName": "OU=Team"}], None), ([], None)], ResultStatus.NEGATIVE),
    ("Team", [([{"distinguishedName": "OU=Team"}], None), ([{"sAMAccountName": "alex", "cn": "Alex"}], None)], ResultStatus.SUCCESS),
    ("Team", [([{"distinguishedName": "OU=Team"}], "partial OU lookup"), ([{"sAMAccountName": "alex", "cn": "Alex"}], None)], ResultStatus.FAILED),
])
def test_ldap_ou_results_preserve_scope_records_and_failures(monkeypatch, requested, responses, expected):
    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["ldap"]["path"])
    monkeypatch.setattr(module, "parse_result_attributes", lambda response: response)
    remaining = iter(responses)
    bases = []
    fake = SimpleNamespace(
        host="offline.invalid", playbook_mode=True, last_search_error=None, args=Namespace(ous=requested),
        logger=SimpleNamespace(debug=lambda message: None, highlight=lambda message: None, fail=lambda message: None),
    )

    def search(*args, **kwargs):
        bases.append(kwargs.get("baseDN"))
        rows, fake.last_search_error = next(remaining)
        return rows

    fake.search = search
    result = module.ldap.ous(fake)

    assert result.status is expected
    assert result.data.requested_ou == requested
    assert result.data.ous == responses[0][0]
    if len(responses) == 2:
        assert bases == [None, "OU=Team"]
        assert result.data.search_base == "OU=Team"
        assert result.data.users == responses[1][0]
    if expected is ResultStatus.FAILED:
        assert result.error


def test_ldap_empty_results_keep_search_failure_distinct_from_no_matches():
    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["ldap"]["path"])
    fake = SimpleNamespace(
        args=SimpleNamespace(users=[], users_export=None, query=["(objectClass=user)", "sAMAccountName"]),
        logger=SimpleNamespace(debug=lambda message: None, fail=lambda message: None),
        playbook_mode=True, host="offline.invalid", domain="EXAMPLE", baseDN="DC=example,DC=test", last_search_error=None,
    )

    def failed_search(*args, **kwargs):
        fake.last_search_error = "LDAP access denied"
        return []

    fake.search = failed_search
    assert module.ldap.users(fake).status is ResultStatus.FAILED
    assert module.ldap.query(fake).error == "LDAP access denied"
    assert module.ldap.pass_pol(fake).status is ResultStatus.FAILED

    def empty_search(*args, **kwargs):
        fake.last_search_error = None
        return []

    fake.search = empty_search
    assert module.ldap.users(fake).status is ResultStatus.NEGATIVE
    assert module.ldap.pass_pol(fake).status is ResultStatus.NEGATIVE


@pytest.mark.parametrize("protocol", sorted(ProtocolLoader().get_protocols()))
def test_every_protocol_can_be_constructed_without_starting_a_connection(monkeypatch, protocol):
    monkeypatch.setattr(connection, "resolver", lambda self, target: {"host": "192.0.2.1", "is_ipv6": False, "is_link_local_ipv6": False})
    args, _ = gen_cli_args([protocol, "offline.invalid"])
    loader = ProtocolLoader()
    protocol_class = getattr(loader.load_protocol(loader.get_protocols()[protocol]["path"]), protocol)

    obj = protocol_class(args, object(), "offline.invalid", defer_flow=True)

    assert obj.host == "192.0.2.1"


def test_parser_initialization_failure_is_recorded(monkeypatch):
    def broken_parser(*args, **kwargs):
        raise RuntimeError("parser unavailable")

    monkeypatch.setattr(playbook_runner, "gen_cli_args", broken_parser)
    host = HostContext("offline.invalid", [])
    session = host.smb(stop_on_error=False)
    assert session.result.status is ResultStatus.FAILED
    assert session.result.error == "parser unavailable"
    assert host.run.results == [session.result]


def test_ldap_group_resolves_foreign_member_even_when_other_members_fill_count(monkeypatch):
    loader = ProtocolLoader()
    module = loader.load_protocol(loader.get_protocols()["ldap"]["path"])
    monkeypatch.setattr(module, "parse_result_attributes", lambda response: response)
    foreign = "CN=S-1-5-21-1-2-3-1100,CN=ForeignSecurityPrincipals,DC=essos,DC=local"
    fake = SimpleNamespace(host="offline.invalid", playbook_mode=True, last_search_error=None, scope="wholeSubtree", args=Namespace(groups="Spys"), logger=SimpleNamespace(debug=lambda message: None, highlight=lambda message: None))
    searches = []

    def search(search_filter, attributes, **kwargs):
        searches.append((search_filter, attributes, kwargs, fake.scope))
        if len(searches) == 1:
            return [{"distinguishedName": "CN=Spys,DC=essos,DC=local", "objectSid": "S-1-5-21-4-5-6-1100", "member": ["CN=Alice,DC=essos,DC=local", foreign]}]
        if len(searches) == 2:
            return [{"distinguishedName": "CN=Alice,DC=essos,DC=local", "sAMAccountName": "alice"}, {"distinguishedName": "CN=Other,DC=essos,DC=local", "sAMAccountName": "other"}]
        return [{"distinguishedName": foreign, "cn": "S-1-5-21-1-2-3-1100", "objectSid": "S-1-5-21-1-2-3-1100", "objectClass": ["foreignSecurityPrincipal"]}]

    fake.search = search
    result = module.ldap.groups(fake)
    assert result.status is ResultStatus.SUCCESS
    assert len(searches) == 3
    assert searches[-1][0] == "(objectClass=*)"
    assert searches[-1][2]["baseDN"] == foreign
    assert searches[-1][3] == module.ldapasn1_impacket.Scope("baseObject")
    assert fake.scope == "wholeSubtree"
    assert "objectSid" in searches[-1][1]
    assert any(member.get("objectSid") == "S-1-5-21-1-2-3-1100" for member in result.data.members)
