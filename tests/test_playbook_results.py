"""Local tests for the playbook result contract."""

from dataclasses import dataclass
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase

from nxc.connection import connection
from nxc.loaders.moduleloader import ModuleLoader
from nxc.modules import enum_ca as enum_ca_module
from nxc.modules import smbghost as smbghost_module
from nxc.modules import spooler as spooler_module
from nxc.modules import webdav as webdav_module
from nxc.playbooks.capture import RecordingLogger, captured_result
from nxc.playbooks.contracts import ResultContractError, validate_module_result
from nxc.playbooks.results import ActionResult, Artifact, CredentialRef, OutputEvent, ResultStatus
from nxc.playbooks.runner import ConnectionData, HostContext, ProtocolSession
import nxc.playbooks.runner as playbook_runner


@dataclass
class SharesData:
    names: list[str]
    credential: CredentialRef


class SharesModule:
    name = "shares"
    result_type = SharesData


class TestPlaybookResults(TestCase):
    def test_captured_failure_retains_event_and_return_value(self):
        result = captured_result("smb", "legacy", "offline.invalid", {"found": 0}, [OutputEvent("fail", "access denied")])

        assert result.status is ResultStatus.FAILED
        assert result.error == "access denied"
        assert result.to_dict()["data"] == {
            "events": [{"level": "fail", "message": "access denied"}],
            "return_value": {"found": 0},
            "records": [{"level": "fail", "kind": "text", "value": "access denied", "key": None}],
            "fields": {},
        }

    def test_custom_module_with_builtin_name_keeps_its_own_result_type(self):
        with TemporaryDirectory() as folder:
            first = Path(folder) / "first" / "same.py"
            second = Path(folder) / "second" / "same.py"
            for path, value in ((first, 1), (second, 2)):
                path.parent.mkdir()
                path.write_text(f"from dataclasses import dataclass\n@dataclass\nclass Result:\n    value: int = {value}\n", encoding="utf-8")

            first_module = ModuleLoader.load_module_file(str(first))
            second_module = ModuleLoader.load_module_file(str(second))

            assert first_module.Result().value == 1
            assert second_module.Result().value == 2
            assert first_module.__name__ != second_module.__name__

    def test_module_result_is_typed_and_json_compatible(self):
        result = ActionResult(
            protocol="smb",
            action="shares",
            target="host.example",
            status=ResultStatus.SUCCESS,
            data=SharesData(names=["Public"], credential=CredentialRef("smb", 7)),
            artifacts=[Artifact(Path("/tmp/shares.json"), "json")],
            inputs={"filter": "READ", "credential": CredentialRef("smb", 7)},
        )

        assert validate_module_result(SharesModule(), result, "smb", "host.example") is result
        assert result.to_dict()["data"] == {"names": ["Public"], "credential": {"protocol": "smb", "id": 7}}
        assert result.to_dict()["artifacts"] == [{"path": "/tmp/shares.json", "kind": "json"}]
        assert result.to_dict()["inputs"] == {"filter": "READ", "credential": {"protocol": "smb", "id": 7}}

    def test_module_without_declared_data_is_rejected(self):
        class LegacyModule:
            name = "legacy"

        message = None
        try:
            validate_module_result(LegacyModule(), None, "smb", "host.example")
        except ResultContractError as e:
            message = str(e)
        assert message is not None
        assert "result_type" in message


def test_recording_logger_preserves_original_message():
    forwarded = []
    logger = RecordingLogger(SimpleNamespace(info=lambda message: forwarded.append(message)))

    logger.info("password=hunter2")

    assert logger.events[0].message == "password=hunter2"
    assert forwarded == ["password=hunter2"]


def test_legacy_parser_preserves_repeated_fields_and_native_json_values():
    events = [
        OutputEvent("highlight", "User Count   : 2"),
        OutputEvent("highlight", "User Count: 3"),
        OutputEvent("info", '{"Enabled": true, "Groups": ["Admins", "Users"]}'),
        OutputEvent("info", "Identifier: 0012"),
        OutputEvent("display", "Service check completed"),
    ]

    result = captured_result("smb", "custom", "offline.invalid", None, events)

    assert result.data.values("User Count") == [2, 3]
    assert result.data.values("enabled") == [True]
    assert result.data.values("groups") == [["Admins", "Users"]]
    assert result.data.values("identifier") == ["0012"]
    assert result.data.values("missing") == []
    assert result.data.contains("CHECK COMPLETED", level="display")
    assert not result.data.contains("CHECK COMPLETED", level="fail")
    assert result.events == events
    assert [record.kind for record in result.data.records] == ["key_value", "key_value", "json", "key_value", "text"]


def test_legacy_parser_keeps_urls_and_malformed_json_as_text():
    messages = ['{"invalid": }', "http://offline.invalid/path", "  unstructured output  "]
    result = captured_result("smb", "custom", "offline.invalid", None, [OutputEvent("info", message) for message in messages])

    assert result.data.fields == {}
    assert [record.value for record in result.data.records] == messages
    assert all(record.kind == "text" for record in result.data.records)


def test_user_installed_module_returns_typed_result_without_network(monkeypatch):
    with TemporaryDirectory() as folder:
        module_path = Path(folder) / "modules" / "example_custom.py"
        module_path.parent.mkdir()
        module_path.write_text(
            "from dataclasses import dataclass\n"
            "from nxc.helpers.misc import CATEGORY\n"
            "from nxc.playbooks.results import ActionResult, ResultStatus\n"
            "class NXCModule:\n"
            "    name = 'example_custom'\n"
            "    description = 'Offline contract example'\n"
            "    category = CATEGORY.ENUMERATION\n"
            "    supported_protocols = ['smb']\n"
            "    @dataclass\n"
            "    class ResultData:\n"
            "        count: int\n"
            "    result_type = ResultData\n"
            "    def options(self, context, module_options):\n"
            "        self.count = int(module_options.get('COUNT', '1'))\n"
            "    def on_login(self, context, connection):\n"
            "        context.log.display('finding logged')\n"
            "        return ActionResult('smb', self.name, connection.host, ResultStatus.SUCCESS, self.ResultData(self.count))\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(playbook_runner, "NXC_PATH", folder)
        host = HostContext("offline.invalid", [])
        args = Namespace(protocol="smb", module=[], module_options=[], playbook_mode=True)
        fake = SimpleNamespace(
            host="offline.invalid", hostname="offline.invalid", port=445, local_ip=None, db=object(), args=args,
            logger=SimpleNamespace(debug=lambda message: None), admin_privs=False, playbook_mode=True, action_results=[],
            call_modules=None,
        )
        fake.call_modules = lambda: connection.call_modules(fake)
        fake.run_module_hook = lambda *args, **kwargs: connection.run_module_hook(fake, *args, **kwargs)
        connected = ActionResult("smb", "connect", fake.host, ResultStatus.SUCCESS, ConnectionData(True, True, False))
        session = ProtocolSession(host, "smb", fake, args, fake.db, SimpleNamespace(dispose=lambda: None), connected)

        result = session.module("example_custom", count=3)

        assert result.ok
        assert result.data.count == 3
        assert result.inputs == {"count": 3}
        assert [event.message for event in result.events] == ["finding logged"]
        assert host.run.to_dict()["results"][0]["data"] == {"count": 3}


def test_legacy_user_module_fails_before_options_or_hooks(monkeypatch):
    with TemporaryDirectory() as folder:
        module_path = Path(folder) / "modules" / "legacy_custom.py"
        module_path.parent.mkdir()
        module_path.write_text(
            "from nxc.helpers.misc import CATEGORY\n"
            "class NXCModule:\n"
            "    name = 'legacy_custom'\n"
            "    description = 'Legacy output example'\n"
            "    category = CATEGORY.ENUMERATION\n"
            "    supported_protocols = ['smb']\n"
            "    def options(self, context, module_options):\n"
            "        context.log.info('option accepted')\n"
            "    def on_login(self, context, connection):\n"
            "        context.log.display('Count: 1')\n"
            "        connection.logger.success('connection message')\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(playbook_runner, "NXC_PATH", folder)
        host = HostContext("offline.invalid", [])
        args = Namespace(protocol="smb", module=[], module_options=[], playbook_mode=True)
        fake = SimpleNamespace(
            host="offline.invalid", hostname="offline.invalid", port=445, local_ip=None, db=object(), args=args,
            logger=SimpleNamespace(debug=lambda message: None, success=lambda message: None),
            admin_privs=False, playbook_mode=True, action_results=[], call_modules=None,
        )
        original_logger = fake.logger
        fake.call_modules = lambda: connection.call_modules(fake)
        fake.run_module_hook = lambda *args, **kwargs: connection.run_module_hook(fake, *args, **kwargs)
        connected = ActionResult("smb", "connect", fake.host, ResultStatus.SUCCESS, ConnectionData(True, True, False))
        session = ProtocolSession(host, "smb", fake, args, fake.db, SimpleNamespace(dispose=lambda: None), connected)

        result = session.module("legacy_custom", stop_on_error=False)

        assert result.status is ResultStatus.FAILED
        assert "must declare a dataclass result_type" in result.error
        assert not result.events
        assert fake.logger is original_logger


def test_module_stops_before_admin_hook_by_default_and_can_continue(monkeypatch):
    with TemporaryDirectory() as folder:
        module_path = Path(folder) / "modules" / "dual_hook.py"
        module_path.parent.mkdir()
        module_path.write_text(
            "from dataclasses import dataclass\n"
            "from nxc.helpers.misc import CATEGORY\n"
            "from nxc.playbooks.results import ActionResult, ResultStatus\n"
            "class NXCModule:\n"
            "    name = 'dual_hook'\n"
            "    description = 'Two hook contract example'\n"
            "    category = CATEGORY.ENUMERATION\n"
            "    supported_protocols = ['smb']\n"
            "    @dataclass\n"
            "    class ResultData:\n"
            "        stage: str\n"
            "    result_type = ResultData\n"
            "    def options(self, context, module_options):\n"
            "        pass\n"
            "    def on_login(self, context, connection):\n"
            "        return ActionResult('smb', self.name, connection.host, ResultStatus.FAILED, self.ResultData('login'), error='first hook failed')\n"
            "    def on_admin_login(self, context, connection):\n"
            "        return ActionResult('smb', self.name, connection.host, ResultStatus.SUCCESS, self.ResultData('admin'))\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(playbook_runner, "NXC_PATH", folder)
        host = HostContext("offline.invalid", [])
        args = Namespace(protocol="smb", module=[], module_options=[], playbook_mode=True)
        fake = SimpleNamespace(
            host="offline.invalid", hostname="offline.invalid", port=445, local_ip=None, db=object(), args=args,
            logger=SimpleNamespace(debug=lambda message: None), admin_privs=True, playbook_mode=True, action_results=[], modules=[],
        )
        fake.call_modules = lambda: connection.call_modules(fake)
        fake.run_module_hook = lambda *args, **kwargs: connection.run_module_hook(fake, *args, **kwargs)
        connected = ActionResult("smb", "connect", fake.host, ResultStatus.SUCCESS, ConnectionData(True, True, False))
        session = ProtocolSession(host, "smb", fake, args, fake.db, SimpleNamespace(dispose=lambda: None), connected)

        try:
            session.module("dual_hook")
        except playbook_runner.PlaybookStepError:
            pass
        else:
            raise AssertionError("The failed login hook should stop the module")
        assert [result.data.stage for result in host.run.results] == ["login"]

        continued = session.module("dual_hook", stop_on_error=False)

        assert [result.data.stage for result in continued] == ["login", "admin"]
        assert [result.to_dict()["hook"] for result in continued] == ["on_login", "on_admin_login"]


def test_module_option_failure_preserves_its_messages(monkeypatch):
    with TemporaryDirectory() as folder:
        module_path = Path(folder) / "modules" / "bad_options.py"
        module_path.parent.mkdir()
        module_path.write_text(
            "from dataclasses import dataclass\n"
            "from nxc.helpers.misc import CATEGORY\n"
            "class NXCModule:\n"
            "    @dataclass\n"
            "    class ResultData:\n"
            "        count: int = 0\n"
            "    result_type = ResultData\n"
            "    name = 'bad_options'\n"
            "    description = 'Option failure example'\n"
            "    category = CATEGORY.ENUMERATION\n"
            "    supported_protocols = ['smb']\n"
            "    def options(self, context, module_options):\n"
            "        context.log.fail('Missing required option')\n"
            "        return False\n"
            "    def on_login(self, context, connection):\n"
            "        raise AssertionError('hook should not run')\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(playbook_runner, "NXC_PATH", folder)
        host = HostContext("offline.invalid", [])
        args = Namespace(protocol="smb", module=[], module_options=[], playbook_mode=True)
        fake = SimpleNamespace(host="offline.invalid", args=args)
        connected = ActionResult("smb", "connect", fake.host, ResultStatus.SUCCESS, ConnectionData(True, True, False))
        session = ProtocolSession(host, "smb", fake, args, object(), SimpleNamespace(dispose=lambda: None), connected)

        result = session.module("bad_options", stop_on_error=False)

        assert result.status is ResultStatus.FAILED
        assert result.events[0].message == "Missing required option"


def test_webdav_module_returns_typed_positive_and_negative_results(monkeypatch):
    class RemoteFile:
        available = True

        def __init__(self, *args, **kwargs):
            pass

        def open_file(self):
            if not self.available:
                raise MissingPipe

        def close(self):
            pass

    class MissingPipe(Exception):
        def getErrorCode(self):
            return webdav_module.nt_errors.STATUS_OBJECT_NAME_NOT_FOUND

    monkeypatch.setattr(webdav_module, "RemoteFile", RemoteFile)
    monkeypatch.setattr(webdav_module, "SessionError", MissingPipe)
    context = SimpleNamespace(log=SimpleNamespace(highlight=lambda message: None))
    conn = SimpleNamespace(host="offline.invalid", args=Namespace(protocol="smb"), conn=SimpleNamespace(getRemoteHost=lambda: "offline.invalid"))
    module = webdav_module.NXCModule()
    module.options(context, {})

    enabled = module.on_login(context, conn)
    RemoteFile.available = False
    absent = module.on_login(context, conn)

    assert validate_module_result(module, enabled, "smb", conn.host).data.enabled is True
    assert enabled.data.remote_host == "offline.invalid"
    assert validate_module_result(module, absent, "smb", conn.host).status is ResultStatus.NEGATIVE


def test_spooler_module_returns_typed_absence_without_network(monkeypatch):
    class FakeDce:
        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeRpc:
        def __init__(self, *args, **kwargs):
            self.rpc_transport = None

        def create_tcp_transport(self, target_ip):
            return self

        def get_dce_rpc(self):
            return FakeDce()

    monkeypatch.setattr(spooler_module, "NXCRPCConnection", FakeRpc)
    monkeypatch.setattr(spooler_module.epm, "hept_lookup", lambda *args, **kwargs: [])
    context = SimpleNamespace(log=SimpleNamespace(debug=lambda message: None))
    conn = SimpleNamespace(host="offline.invalid", args=Namespace(protocol="smb"), kerberos=False)
    module = spooler_module.NXCModule()
    module.options(context, {})

    result = module.on_login(context, conn)

    assert validate_module_result(module, result, "smb", conn.host).status is ResultStatus.NEGATIVE
    assert result.data.enabled is False
    assert result.data.endpoints == []


def test_enum_ca_module_returns_typed_absence_without_network(monkeypatch):
    class FakeDce:
        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeRpc:
        def __init__(self, *args, **kwargs):
            self.rpc_transport = None

        def create_tcp_transport(self, target_ip):
            return self

        def get_dce_rpc(self):
            return FakeDce()

    monkeypatch.setattr(enum_ca_module, "NXCRPCConnection", FakeRpc)
    monkeypatch.setattr(enum_ca_module.epm, "hept_lookup", lambda *args, **kwargs: [])
    context = SimpleNamespace(hash=[], log=SimpleNamespace(debug=lambda message: None))
    conn = SimpleNamespace(host="offline.invalid", username="", password="", domain="", hash="", kerberos=False, args=Namespace(protocol="smb"))
    module = enum_ca_module.NXCModule()
    module.options(context, {})

    result = module.on_login(context, conn)

    assert validate_module_result(module, result, "smb", conn.host).status is ResultStatus.NEGATIVE
    assert result.data.adcs_found is False
    assert result.data.web_enrollment_found is False


def test_enum_ca_module_returns_typed_adcs_and_web_enrollment(monkeypatch):
    class FakeDce:
        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeRpc:
        def __init__(self, *args, **kwargs):
            self.rpc_transport = None

        def create_tcp_transport(self, target_ip):
            return self

        def get_dce_rpc(self):
            return FakeDce()

    monkeypatch.setattr(enum_ca_module, "NXCRPCConnection", FakeRpc)
    monkeypatch.setattr(enum_ca_module.epm, "hept_lookup", lambda *args, **kwargs: [{"tower": {"Floors": ["fake-uuid"]}}])
    monkeypatch.setattr(enum_ca_module.uuid, "string_to_uuidtup", lambda value: value)
    monkeypatch.setattr(enum_ca_module.uuid, "uuidtup_to_bin", lambda value: b"x" * 18)
    monkeypatch.setitem(enum_ca_module.epm.KNOWN_UUIDS, b"x" * 18, "certsrv.exe")
    monkeypatch.setattr(enum_ca_module.requests, "get", lambda url, timeout: SimpleNamespace(status_code=401, headers={"WWW-Authenticate": "NTLM"}))
    context = SimpleNamespace(hash=[], log=SimpleNamespace(debug=lambda message: None, highlight=lambda message: None))
    conn = SimpleNamespace(host="offline.invalid", username="", password="", domain="", hash="", kerberos=False, args=Namespace(protocol="smb"))
    module = enum_ca_module.NXCModule()
    module.options(context, {})

    result = module.on_login(context, conn)

    assert validate_module_result(module, result, "smb", conn.host).status is ResultStatus.SUCCESS
    assert result.data.adcs_found is True
    assert result.data.web_enrollment_found is True
    assert result.data.enrollment_url == "http://offline.invalid/certsrv/certfnsh.asp"


def test_smbghost_module_returns_typed_positive_and_negative_results(monkeypatch):
    context = SimpleNamespace(log=SimpleNamespace(highlight=lambda message: None))
    conn = SimpleNamespace(host="offline.invalid", args=Namespace(protocol="smb"))
    module = smbghost_module.NXCModule()
    monkeypatch.setattr(module, "perform_attack", lambda target: True)

    positive = module.on_login(context, conn)
    monkeypatch.setattr(module, "perform_attack", lambda target: False)
    negative = module.on_login(context, conn)

    assert validate_module_result(module, positive, "smb", conn.host).status is ResultStatus.SUCCESS
    assert positive.data.potentially_vulnerable is True
    assert validate_module_result(module, negative, "smb", conn.host).status is ResultStatus.NEGATIVE


def test_ms17_010_module_returns_typed_detection_without_network():
    path = Path(__file__).resolve().parents[1] / "nxc" / "modules" / "ms17-010.py"
    module = ModuleLoader.load_module_file(str(path)).NXCModule()
    context = SimpleNamespace(log=SimpleNamespace(highlight=lambda message: None, debug=lambda message: None))
    conn = SimpleNamespace(host="offline.invalid", args=Namespace(protocol="smb"))
    module.options(context, {})
    module.check = lambda target: True

    positive = module.on_login(context, conn)
    module.check = lambda target: False
    negative = module.on_login(context, conn)

    assert validate_module_result(module, positive, "smb", conn.host).status is ResultStatus.SUCCESS
    assert positive.data.vulnerable is True
    assert validate_module_result(module, negative, "smb", conn.host).status is ResultStatus.NEGATIVE


def test_ms17_010_packet_check_returns_positive_without_network(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "nxc" / "modules" / "ms17-010.py"
    loaded = ModuleLoader.load_module_file(str(path))
    module = loaded.NXCModule()
    module.logger = SimpleNamespace(debug=lambda message: None, highlight=lambda message: None, fail=lambda message: None)
    for name in ("negotiate_proto_request", "session_setup_andx_request", "tree_connect_andx_request", "peeknamedpipe_request", "trans2_request"):
        monkeypatch.setattr(module, name, lambda *args: b"packet")
    headers = iter([
        SimpleNamespace(user_id=1),
        SimpleNamespace(tree_id=1, process_id=1, user_id=1, multiplex_id=1),
        SimpleNamespace(error_class=5, reserved1=2, error_code=0xC000),
        SimpleNamespace(multiplex_id=0),
    ])
    monkeypatch.setattr(loaded, "SmbHeader", lambda buffer: next(headers))

    class FakeSocket:
        def settimeout(self, value):
            pass

        def connect(self, target):
            pass

        def send(self, data):
            pass

        def recv(self, size):
            return b"x" * 128

        def close(self):
            pass

    monkeypatch.setattr(loaded.socket, "socket", lambda *args: FakeSocket())

    assert module.check("offline.invalid") is True
