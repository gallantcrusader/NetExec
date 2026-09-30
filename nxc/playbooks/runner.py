"""Run Python playbooks once per target with reusable protocol sessions."""

import argparse
import contextlib
import hashlib
import importlib.util
import inspect
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from os.path import join as path_join
from pathlib import Path

import nxc
from nxc.cli import gen_cli_args
from nxc.config import nxc_config, nxc_workspace
from nxc.database import create_db_engine
from nxc.loaders.moduleloader import ModuleLoader
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.logger import nxc_logger
from nxc.parsers.ip import process_targets
from nxc.paths import NXC_PATH, WORKSPACE_DIR
from nxc.playbooks.capture import RecordingLogger, captured_result
from nxc.playbooks.contracts import ResultContractError, validate_action_result
from nxc.playbooks.results import ActionResult, CredentialRef, ModuleResult, OutputEvent, ResultStatus, json_value


class PlaybookStepError(RuntimeError):
    """Stop work on one host after an unhandled step failure."""


# Sentinel for step options that fall back to the host-level default when the
# caller does not pass them. An explicit value on a call always wins over the
# host default set with host.defaults(...).
_UNSET = object()

MULTI_VALUE_OPTIONS = {"username", "password", "hash", "aesKey", "cred_id"}
RESERVED_CONNECTION_OPTIONS = {"protocol", "target", "module", "module_options", "playbook_mode"}


@dataclass
class ConnectionData:
    connected: bool
    authenticated: bool
    anonymous: bool
    signing_required: bool | None = None
    channel_binding: str | None = None
    credential: CredentialRef | None = None
    guest: bool = False
    admin_privileges: bool | None = None
    admin_check_error: str | None = None


@dataclass
class FailureData:
    message: str


@dataclass
class SkippedData:
    reason: str


@dataclass
class VerdictData:
    """Default payload for a host.finding(...) verdict when no custom data is given."""

    finding: str
    ok: bool
    detail: str | None = None


class _EvidenceCollector:
    """Collects the host.run.results indices recorded within a host.evidence() block."""

    def __init__(self):
        self.indices = []


def format_module_option(value):
    """Convert Python values to the module option text NetExec expects."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def normalize_connection_option(name, value, current):
    """Keep CLI multi-value arguments in the list form protocols expect."""
    if name in MULTI_VALUE_OPTIONS or isinstance(current, list):
        return list(value) if isinstance(value, (list, tuple)) else [value]
    return value


def normalize_action_option(name, value, nargs, append=False):
    """Normalize multi-value action arguments using the protocol CLI contract."""
    if append and isinstance(nargs, int) and nargs > 0:
        groups = list(value) if isinstance(value, (list, tuple)) else [value]
        if groups and not isinstance(groups[0], (list, tuple)):
            groups = [groups]
        return [normalize_action_option(name, group, nargs) for group in groups]
    if nargs in ("*", "+") or (isinstance(nargs, int) and nargs > 0):
        values = list(value) if isinstance(value, (list, tuple)) else [] if value is None else [value]
        if nargs == "+" and not values:
            raise ValueError(f"Option {name} requires at least one value")
        if isinstance(nargs, int) and len(values) != nargs:
            raise ValueError(f"Option {name} requires {nargs} values; received {len(values)}")
        return values
    return value


@dataclass
class HostRun:
    target: str
    results: list[ActionResult] = field(default_factory=list)
    error: str | None = None
    allowed_targets: list[str] = field(default_factory=list)

    @property
    def failed(self):
        return bool(self.error) or any(result.status is ResultStatus.FAILED for result in self.results)

    def to_dict(self):
        status = "failed" if self.error else "completed_with_errors" if any(result.status is ResultStatus.FAILED for result in self.results) else "success"
        return {"target": self.target, "status": status, "results": [result.to_dict() for result in self.results], "error": self.error, "allowed_targets": self.allowed_targets}


@dataclass
class WorkflowState:
    """Sessions and ordered evidence for one root target's workflow."""

    run: HostRun
    allowed_targets: tuple[str, ...]
    hosts: dict[str, "HostContext"] = field(default_factory=dict)
    step_defaults: dict = field(default_factory=dict)
    evidence_stack: list = field(default_factory=list)


class ProtocolSession:
    """Expose protocol actions and modules through an open connection."""

    def __init__(self, host, protocol, connection, args, db, engine, result, option_nargs=None, append_options=()):
        self.host = host
        self.protocol = protocol
        self.connection = connection
        self.args = args
        self.db = db
        self.engine = engine
        self.result = result
        self.option_nargs = option_nargs or {}
        self.append_options = set(append_options)

    @property
    def ok(self):
        return self.result.ok and not getattr(self.connection, "playbook_unusable_reason", None)

    @property
    def authenticated(self):
        """True when a real (non-anonymous, non-guest) login succeeded on this session."""
        return self.ok and isinstance(self.result.data, ConnectionData) and bool(self.result.data.authenticated)

    @property
    def credential(self):
        """The stored credential reference for this login, or None (reusable via credential=)."""
        return self.result.data.credential if isinstance(self.result.data, ConnectionData) else None

    @property
    def admin(self):
        """Local-admin state on the target: True/False, or None when unknown or unchecked."""
        return self.result.data.admin_privileges if isinstance(self.result.data, ConnectionData) else None

    def _stop(self, stop_on_error):
        """Resolve a per-call stop_on_error against the host default (explicit wins)."""
        if stop_on_error is _UNSET:
            return self.host.step_defaults.get("stop_on_error", True)
        return stop_on_error

    def action(self, name, *, stop_on_error=_UNSET, **options):
        """Run one CLI action on this connection and record its output."""
        stop_on_error = self._stop(stop_on_error)
        original_logger = getattr(self.connection, "logger", None)
        recorder = RecordingLogger(original_logger) if original_logger is not None else None
        try:
            if not self.ok:
                raise PlaybookStepError(f"No open {self.protocol} session for {self.host.target}")
            if name not in vars(self.args) or not callable(getattr(self.connection, name, None)):
                raise ValueError(f"Unknown {self.protocol} action: {name}")
            method = getattr(self.connection, name)
            if getattr(method, "requires_admin", False) and not self.connection.admin_privs and getattr(self.args, "exec_method", None) != "mmcexec":
                result = ActionResult(self.protocol, name, self.connection.host, ResultStatus.SKIPPED, SkippedData("Administrative privileges are unavailable"), inputs=options.copy())
                return self.host.record(result, stop_on_error)
            invalid = set(options) - set(vars(self.args))
            if invalid:
                raise ValueError(f"Unknown {self.protocol} option(s): {', '.join(sorted(invalid))}")
            normalized = {key: normalize_action_option(key, value, self.option_nargs.get(key), key in self.append_options) for key, value in options.items()}
            previous = {key: getattr(self.args, key) for key in normalized}
            try:
                for key, value in normalized.items():
                    setattr(self.args, key, value)
                if recorder is not None:
                    self.connection.logger = recorder
                returned = method()
            finally:
                for key, value in previous.items():
                    setattr(self.args, key, value)
                if recorder is not None:
                    self.connection.logger = original_logger
            result = returned if isinstance(returned, ActionResult) else captured_result(self.protocol, name, self.connection.host, returned, recorder.events if recorder else [])
            validate_action_result(result, self.protocol, name, self.connection.host)
            if recorder is not None and result.kind == "typed":
                result.events.extend(recorder.events)
            result.inputs = {**result.inputs, **options}
            json_value(result)
        except (Exception, SystemExit) as e:
            message = str(e) or type(e).__name__
            if recorder is not None:
                recorder.events.append(OutputEvent("exception", message))
                result = captured_result(self.protocol, name, getattr(self.connection, "host", self.host.target), None, recorder.events)
            else:
                result = ActionResult(self.protocol, name, getattr(self.connection, "host", self.host.target), ResultStatus.FAILED, FailureData(message), error=message)
            result.inputs = options.copy()
        return self.host.record(result, stop_on_error)

    def module(self, name, *, stop_on_error=_UNSET, **options):
        """Run a module on this connection and return its results as a ModuleResult."""
        stop_on_error = self._stop(stop_on_error)
        if not self.ok:
            message = f"No open {self.protocol} session for {self.host.target}"
            result = ActionResult(self.protocol, name, self.host.target, ResultStatus.FAILED, FailureData(message), error=message, inputs=options.copy())
            return ModuleResult([self.host.record(result, stop_on_error)])
        old_module = self.args.module
        old_options = self.args.module_options
        old_modules = getattr(self.connection, "modules", None)
        old_stop_on_error = getattr(self.connection, "playbook_stop_on_error", True)
        old_session = getattr(self.connection, "playbook_session", None)
        try:
            try:
                module_path = None
                for folder in (Path(NXC_PATH) / "modules", Path(nxc.__file__).parent / "modules"):
                    candidate = folder / f"{name}.py"
                    if candidate.is_file():
                        module_path = str(candidate)
                        break
                if module_path is None:
                    raise ValueError(f"Unknown module: {name}")
                self.args.module = [name]
                self.args.module_options = [f"{key.upper()}={format_module_option(value)}" for key, value in options.items() if value is not None]
                module = ModuleLoader(self.args, self.db, nxc_logger).init_module(module_path)
                if module is None:
                    raise ResultContractError(f"Module {name} could not be loaded")
                previous_count = len(self.connection.action_results)
                self.connection.modules = [module]
                self.connection.playbook_stop_on_error = stop_on_error
                self.connection.playbook_session = self
                self.connection.call_modules()
                results = self.connection.action_results[previous_count:]
            finally:
                self.args.module = old_module
                self.args.module_options = old_options
                self.connection.modules = old_modules
                self.connection.playbook_stop_on_error = old_stop_on_error
                self.connection.playbook_session = old_session
            if not results:
                results = [ActionResult(self.protocol, name, self.connection.host, ResultStatus.SKIPPED, SkippedData("Required privileges are unavailable"))]
        except (Exception, SystemExit) as e:
            message = str(e) or type(e).__name__
            results = [ActionResult(self.protocol, name, self.connection.host, ResultStatus.FAILED, FailureData(message), error=message, events=list(getattr(e, "events", [])))]
        for result in results:
            result.inputs = {**result.inputs, **options}
            self.host.record(result, stop_on_error=False)
        if stop_on_error:
            for result in results:
                if result.status is ResultStatus.FAILED:
                    raise PlaybookStepError(result.error or f"{self.protocol}.{name} failed")
        return ModuleResult(results)

    def __getattr__(self, name):
        if name in vars(self.args) and callable(getattr(self.connection, name, None)):
            return lambda **options: self.action(name, **options)
        raise AttributeError(name)

    def close(self):
        try:
            self.connection.close_session()
        finally:
            self.engine.dispose()


class HostContext:
    """State shared by all steps for one target."""

    def __init__(self, target, shared_args, connection_defaults=None, allowed_targets=None, *, workflow=None):
        self.target = target
        self.shared_args = shared_args
        self.connection_defaults = dict(connection_defaults or {})
        if workflow is None:
            scope = tuple(dict.fromkeys([target, *(allowed_targets or [])]))
            workflow = WorkflowState(HostRun(target, allowed_targets=list(scope)), scope)
        self.workflow = workflow
        self.run = workflow.run
        workflow.hosts[target] = self
        self.sessions = {}
        self.loader = ProtocolLoader()
        self.protocols = self.loader.get_protocols()

    @property
    def step_defaults(self):
        """Workflow-wide default step options (e.g. stop_on_error) shared across at() peers."""
        return self.workflow.step_defaults

    def defaults(self, **options):
        """Set default step options for this workflow; an explicit value on a call always wins.

        Currently honours ``stop_on_error``. Example: ``host.defaults(stop_on_error=False)``
        makes probe-style playbooks continue past failures without repeating the flag,
        while any individual ``session.action(..., stop_on_error=True)`` still overrides it.
        """
        self.workflow.step_defaults.update(options)
        return self

    def step_default(self, name, fallback=None):
        """Return the workflow default for a step option, or ``fallback`` if unset."""
        return self.workflow.step_defaults.get(name, fallback)

    def at(self, target):
        """Select an explicitly allowed target, keeping this workflow's results."""
        if target not in self.workflow.allowed_targets:
            raise ValueError(f"Target {target!r} is outside this playbook's allowed targets; declare it with --allow-target")
        if target not in self.workflow.hosts:
            HostContext(target, self.shared_args, self.connection_defaults, workflow=self.workflow)
        return self.workflow.hosts[target]

    def record(self, result, stop_on_error=_UNSET):
        if stop_on_error is _UNSET:
            stop_on_error = self.workflow.step_defaults.get("stop_on_error", True)
        result.index = len(self.run.results)
        self.run.results.append(result)
        for collector in self.workflow.evidence_stack:
            collector.indices.append(result.index)
        if result.status is ResultStatus.FAILED and stop_on_error:
            raise PlaybookStepError(result.error or f"{result.protocol}.{result.action} failed")
        return result

    @contextlib.contextmanager
    def evidence(self):
        """Collect the run-result indices recorded inside this block.

        Removes the need to hand-track ``len(host.run.results) - 1`` after each
        step. The yielded object exposes ``.indices`` (a list of ints into
        ``host.run.results``), populated for every result recorded across this and
        any ``host.at()`` peer while the block is active.
        """
        collector = _EvidenceCollector()
        self.workflow.evidence_stack.append(collector)
        try:
            yield collector
        finally:
            self.workflow.evidence_stack.remove(collector)

    def finding(self, name, *, ok=None, status=None, data=None, inputs=None, protocol="playbook", error=None):
        """Record a playbook-level verdict as an ActionResult and return it.

        Pass ``ok=True/False`` for the common SUCCESS/NEGATIVE verdict, or an explicit
        ``status=ResultStatus.…``. Supply your own dataclass as ``data`` to carry
        evidence; when omitted a small VerdictData payload is stored.
        """
        if status is None:
            status = ResultStatus.SUCCESS if ok else ResultStatus.NEGATIVE
        if data is None:
            data = VerdictData(name, status is ResultStatus.SUCCESS, error)
        result = ActionResult(protocol, name, self.target, status, data, inputs=dict(inputs or {}), error=error)
        return self.record(result)

    def credential(self, protocol, credential_id):
        """Refer to a credential already stored by NetExec."""
        return CredentialRef(protocol, int(credential_id))

    def __getattr__(self, name):
        if name in self.protocols:
            return lambda **options: self.connect(name, **options)
        raise AttributeError(name)

    def connect(self, protocol, *, anonymous=False, credential=None, stop_on_error=_UNSET, **options):
        """Reuse one session per protocol and authentication choice on this host."""
        if protocol not in self.protocols:
            raise ValueError(f"Unknown protocol: {protocol}")
        if anonymous and credential is not None:
            raise ValueError("Choose anonymous access or a credential reference")
        args = None
        option_parser = argparse.ArgumentParser(add_help=False)
        engine = None
        db = None
        connection = None
        try:
            args, _, option_parser = gen_cli_args([protocol, self.target, *self.shared_args], with_parser=True)
            args.playbook_mode = True
            defaults = {name: value for name, value in self.connection_defaults.items() if hasattr(args, name)}
            if options.get("local_auth"):
                defaults.pop("domain", None)
            options = {**defaults, **options}
            invalid = (set(options) - set(vars(args))) | (set(options) & RESERVED_CONNECTION_OPTIONS)
            if invalid:
                raise ValueError(f"Unknown {protocol} connection option(s): {', '.join(sorted(invalid))}")
            if (anonymous or credential is not None) and set(options) & MULTI_VALUE_OPTIONS:
                raise ValueError("Authentication options cannot be combined with anonymous access or a credential reference")
            for name, value in options.items():
                setattr(args, name, normalize_connection_option(name, value, getattr(args, name)))
            key = (protocol, anonymous, credential, json.dumps(json_value(options), sort_keys=True))
            if key in self.sessions:
                if self.sessions[key].ok:
                    return self.sessions[key]
                self.sessions.pop(key).close()
            if anonymous:
                args.username = [""]
                args.password = [""]
                args.cred_id = []
            elif credential is not None:
                self.apply_credential(args, credential)
            protocol_info = self.protocols[protocol]
            protocol_class = getattr(self.loader.load_protocol(protocol_info["path"]), protocol)
            protocol_class.config = nxc_config
            engine = create_db_engine(path_join(WORKSPACE_DIR, nxc_workspace, f"{protocol}.db"))
            db = self.loader.load_protocol(protocol_info["dbpath"]).database(engine)
            connection = protocol_class(args, db, self.target, defer_flow=True)
            ready = connection.open_session(anonymous=anonymous)
            guest = bool(getattr(connection, "is_guest", False))
            stored_credential = self.find_stored_credential(protocol, db, connection) if ready and not anonymous and not guest else None
        except Exception as e:
            if connection is not None:
                with contextlib.suppress(Exception):
                    connection.close_session()
            if engine is not None:
                engine.dispose()
            message = str(e) or type(e).__name__
            result = ActionResult(protocol, "connect", self.target, ResultStatus.FAILED, FailureData(message), error=message, inputs={"anonymous": anonymous, "credential": credential, **options}, events=list(getattr(connection, "connection_events", [])))
            session = ProtocolSession(self, protocol, connection, args, db, engine, result, {action.dest: action.nargs for action in option_parser._actions}, {action.dest for action in option_parser._actions if isinstance(action, argparse._AppendAction)})
            self.record(result, stop_on_error)
            return session
        result = ActionResult(
            protocol=protocol,
            action="connect",
            target=self.target,
            status=ResultStatus.SUCCESS if ready else ResultStatus.NEGATIVE,
            data=ConnectionData(
                connected=connection.transport_open,
                authenticated=ready and bool(connection.username or (protocol == "vnc" and connection.password)) and not anonymous and not guest,
                anonymous=anonymous,
                signing_required=getattr(connection, "signing_required", getattr(connection, "signing", None)),
                channel_binding=getattr(connection, "cbt_status", None),
                credential=stored_credential,
                guest=guest,
                admin_privileges=getattr(connection, "admin_check_result", getattr(connection, "admin_privs", None)) if ready and not getattr(args, "no_admin_check", False) else None,
                admin_check_error=getattr(connection, "admin_check_error", None),
            ),
            inputs={"anonymous": anonymous, "credential": credential, **options},
            events=list(getattr(connection, "connection_events", [])),
        )
        session = ProtocolSession(self, protocol, connection, args, db, engine, result)
        if ready:
            self.sessions[key] = session
        else:
            session.close()
        self.record(result, stop_on_error)
        return session

    def apply_credential(self, args, credential):
        """Resolve a source protocol's database ID for another protocol."""
        if not isinstance(credential, CredentialRef) or credential.protocol not in self.protocols:
            raise ValueError("credential must be a valid CredentialRef")
        args.cred_id = []
        args.username = []
        args.password = []
        if hasattr(args, "hash"):
            args.hash = []
        source = self.protocols[credential.protocol]
        engine = create_db_engine(path_join(WORKSPACE_DIR, nxc_workspace, f"{credential.protocol}.db"))
        try:
            db = self.loader.load_protocol(source["dbpath"]).database(engine)
            if not callable(getattr(db, "get_credentials", None)):
                raise ValueError(f"{credential.protocol} does not expose stored credentials")
            rows = db.get_credentials(filter_term=credential.id)
            if not rows or rows[0].id != credential.id:
                raise ValueError(f"Credential {credential.protocol}:{credential.id} does not exist")
            row = rows[0]
            username = getattr(row, "username", None)
            secret = getattr(row, "password", None)
            credtype = getattr(row, "credtype", "plaintext")
            if username is None or secret is None:
                raise ValueError(f"Credential {credential.protocol}:{credential.id} cannot authenticate to {args.protocol}")
            args.username = [username]
            if hasattr(args, "domain"):
                args.domain = getattr(row, "domain", None)
            if credtype == "plaintext":
                args.password = [secret]
            elif credtype == "hash" and hasattr(args, "hash"):
                args.hash = [secret]
            elif credtype == "aesKey" and hasattr(args, "aesKey"):
                args.aesKey = [secret]
                args.kerberos = True
            elif credtype == "key" and credential.protocol == args.protocol == "ssh":
                args.username = []
                args.cred_id = [str(credential.id)]
            else:
                raise ValueError(f"Credential type {credtype} is unsupported by {args.protocol}")
        finally:
            engine.dispose()

    @staticmethod
    def find_stored_credential(protocol, db, connection):
        """Return the exact row written by a successful login, when one exists."""
        get_credentials = getattr(db, "get_credentials", None)
        username = getattr(connection, "credential_username", getattr(connection, "username", None))
        if not callable(get_credentials) or (not username and protocol != "vnc"):
            return None
        password = getattr(connection, "password", None)
        if protocol == "vnc" and not password:
            return None
        ntlm_hash = getattr(connection, "hash", None)
        aes_key = getattr(connection, "aesKey", None)
        successful_type = getattr(connection, "authenticated_credential_type", None)
        successful_secret = getattr(connection, "authenticated_secret", None)
        if successful_type in ("ccache", "certificate"):
            return None
        for row in get_credentials(filter_term=username):
            if row.username != username:
                continue
            if getattr(row, "domain", None) is not None and row.domain != connection.domain:
                continue
            row_type = getattr(row, "credtype", "plaintext")
            if successful_type is not None and row_type != successful_type:
                continue
            if successful_secret is not None:
                valid_secrets = [successful_secret]
                if row_type == "hash" and ":" in successful_secret:
                    valid_secrets.append(successful_secret.rsplit(":", 1)[1])
                if row.password in valid_secrets:
                    return CredentialRef(protocol, row.id)
                continue
            if (row_type in ("plaintext", "key") and password is not None and row.password == password) or (row_type == "hash" and ntlm_hash and row.password == ntlm_hash) or (row_type == "aesKey" and aes_key and row.password == aes_key):
                return CredentialRef(protocol, row.id)
        return None

    def close(self):
        first_error = None
        for host in self.workflow.hosts.values():
            for session in host.sessions.values():
                try:
                    session.close()
                except Exception as e:
                    first_error = first_error or e
            host.sessions.clear()
        if first_error:
            raise first_error


def validate_playbook_function(function, name, argument_count):
    """Reject callbacks that cannot execute synchronously with the runner's arguments."""
    if not callable(function):
        raise ValueError(f"{name} must be a function")
    if inspect.iscoroutinefunction(function) or inspect.isgeneratorfunction(function) or inspect.isasyncgenfunction(function):
        raise ValueError(f"{name} must be synchronous and must not yield")
    try:
        inspect.signature(function).bind(*([None] * argument_count))
    except (TypeError, ValueError) as e:
        raise ValueError(f"{name} must accept {argument_count} positional argument(s): {e}") from e


def load_playbook(path):
    """Load a Python file with one run(host) function."""
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Playbook not found: {path}")
    module_name = f"nxc_playbook_{hashlib.sha256(str(path).encode()).hexdigest()[:16]}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load playbook: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        del sys.modules[module_name]
        raise
    run = getattr(module, "run", None)
    if not callable(run):
        raise ValueError(f"Playbook {path} must define run(host)")
    validate_playbook_function(run, "run(host)", 1)
    return run


def run_host(target, playbook, shared_args, connection_defaults=None, allowed_targets=None):
    """Run a Python workflow for one target and always close its sessions."""
    host = HostContext(target, shared_args, connection_defaults, allowed_targets)
    try:
        playbook(host)
    except (Exception, SystemExit) as e:
        host.run.error = str(e) or type(e).__name__
        nxc_logger.fail(f"Playbook stopped on {target}: {e}")
    finally:
        try:
            host.close()
        except Exception as e:
            host.run.error = host.run.error or f"Error closing a session: {e}"
    return host.run


def main(argv=None):
    """Entry point for ``nxc playbook``."""
    parser = argparse.ArgumentParser(prog="nxc playbook", description="Run one Python playbook per target")
    parser.add_argument("target", nargs="+", help="NetExec target(s) or target file(s)")
    parser.add_argument("script", help="Python file defining run(host)")
    parser.add_argument("--allow-target", nargs="+", action="extend", default=[], help="Additional target(s) available through host.at(), without starting additional workflows")
    parser.add_argument("-u", "--username", nargs="+", default=[])
    parser.add_argument("-p", "--password", nargs="+", default=[])
    parser.add_argument("-id", dest="cred_id", nargs="+", default=[])
    parser.add_argument("-d", "--domain", help="Default authentication domain for protocols that support domains")
    parser.add_argument("--dns-server", help="Default DNS server for protocol connections")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication for supported protocols")
    parser.add_argument("--use-kcache", action="store_true", help="Use Kerberos from KRB5CCNAME for supported protocols")
    parser.add_argument("--kdcHost", help="Domain controller for Kerberos authentication")
    parser.add_argument("-t", "--threads", type=int, default=32)
    parser.add_argument("--results", type=Path, help="Result file (JSON by default)")
    parser.add_argument("--exclude-hosts", nargs="+")
    parser.add_argument("--skip-self", action="store_true")
    options = parser.parse_args(argv)
    if options.threads < 1:
        parser.error("--threads must be positive")
    playbook = load_playbook(options.script)
    writer = getattr(sys.modules[playbook.__module__], "save_results", None)
    if writer is not None:
        validate_playbook_function(writer, "save_results", 2)
    targets = process_targets(argparse.Namespace(target=options.target, protocol="smb", exclude_hosts=options.exclude_hosts, skip_self=options.skip_self))
    if not targets:
        parser.error("no targets matched")
    extra_targets = process_targets(argparse.Namespace(target=options.allow_target, protocol="smb", exclude_hosts=options.exclude_hosts, skip_self=options.skip_self)) if options.allow_target else []
    allowed_targets = list(dict.fromkeys([*targets, *extra_targets]))
    shared_args = []
    if options.username:
        shared_args.extend(["-u", *options.username])
    if options.password:
        shared_args.extend(["-p", *options.password])
    if options.cred_id:
        shared_args.extend(["-id", *options.cred_id])
    runs = [None] * len(targets)
    connection_defaults = {name: getattr(options, name) for name in ("domain", "dns_server") if getattr(options, name) is not None}
    connection_defaults.update({name: getattr(options, name) for name in ("kerberos", "use_kcache", "kdcHost") if getattr(options, name)})
    with ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = {executor.submit(run_host, target, playbook, shared_args, connection_defaults, allowed_targets): index for index, target in enumerate(targets)}
        for future in as_completed(futures):
            runs[futures[future]] = future.result()
    results_path = options.results or Path(NXC_PATH) / "playbooks" / f"{Path(options.script).stem}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    if writer is not None:
        writer(runs, results_path)
        if not results_path.is_file():
            raise ValueError(f"save_results did not create {results_path}")
    else:
        with results_path.open("w", encoding="utf-8") as file:
            json.dump({"schema_version": 1, "hosts": [run.to_dict() for run in runs]}, file, indent=2)
    nxc_logger.success(f"Saved playbook results to {results_path}")
    return 1 if any(run.failed for run in runs) else 0
