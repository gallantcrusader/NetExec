"""Authenticated access sweep — run this the moment you have one credential.

Given a single credential (password, NT hash with -H, or Kerberos with -k) it
probes every protocol and reports exactly what that identity can reach and read:
SMB shares (spidered and fully downloaded), the full LDAP directory, roastable
and delegation-abusable accounts, LAPS/gMSA it can read, MSSQL logins/links/
impersonation, WinRM command access, plus detection-only checks for the usual AD
CVEs and infrastructure (ADCS, SCCM).

It is read-only and detection-only: nothing is exploited, no coercion is fired,
no relay is set up. Readable SMB shares are fully downloaded so you can see and
keep everything this credential can take.

    nxc playbook <targets> examples/playbooks/master_playbook_authenticated.py -u USER -p PASS -d DOMAIN
    nxc playbook <targets> examples/playbooks/master_playbook_authenticated.py -u USER -H NTHASH -d DOMAIN
    nxc playbook <targets> examples/playbooks/master_playbook_authenticated.py -u USER -p PASS -k --dns-server DC_IP

Results print as a per-host checklist and are saved to NXC_PATH.
"""

from dataclasses import dataclass, field

from nxc.playbooks.results import ResultStatus

# Effectively-unlimited spider download cap (bytes) so "read" really means "grabbed".
SPIDER_MAX = 64 * 1024 * 1024 * 1024

# This sweep uses the single credential supplied on the command line (-u/-p, -H, or -k).
IDENTITIES = [
    ("credential", {}),
]
AUTH_MODE = True  # authenticated sweep: also run kerberoast / LAPS / BloodHound / mssql_priv
VULN_IDENT = {}  # host-level vuln detection runs as the supplied credential
CHECKLIST_TITLE = "AUTHENTICATED ACCESS CHECKLIST"
FINDING_NAME = "master_playbook_authenticated"


# --------------------------------------------------------------------------- #
# result containers
# --------------------------------------------------------------------------- #
@dataclass
class ProtoResult:
    protocol: str
    reachable: bool = False
    authenticated: bool = False
    guest: bool = False
    admin: object = None
    signing_required: object = None
    channel_binding: object = None
    facts: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


@dataclass
class IdentityReport:
    label: str
    protocols: dict = field(default_factory=dict)


@dataclass
class HostReport:
    target: str
    identities: list = field(default_factory=list)
    vulns: dict = field(default_factory=dict)
    vuln_detail: dict = field(default_factory=dict)
    any_access: bool = False


# --------------------------------------------------------------------------- #
# helpers (every one swallows Exception AND SystemExit so a single protocol or
# module that hard-exits can never abort the whole sweep)
# --------------------------------------------------------------------------- #
def _try(pr, name, fn):
    """Run one check; record its result under facts[name], swallow failures."""
    try:
        value = fn()
        if value is not None:
            pr.facts[name] = value
        return value
    except (Exception, SystemExit) as e:
        pr.errors.append(f"{name}: {type(e).__name__}: {e}")
        return None


def _count_fields(result):
    """Count the primary list on a result that already succeeded."""
    data = getattr(result, "data", None)
    for attr in ("users", "groups", "computers", "entries", "records", "members", "servers", "accounts", "templates", "links", "rows"):
        seq = getattr(data, attr, None)
        if isinstance(seq, (list, dict)):
            return len(seq)
    return "ran"  # succeeded but no recognizable collection to count


# Query-level blocks (the whole search was refused) vs per-item errors. Only the
# former mean "denied"; roasting/delegation actions are "captured" and log their
# findings as records even while their overall status is marked failed.
_BLOCKED = ("must be completed", "operationserror", "requires a username",
            "invalid credentials", "strongerauthrequired", "status_access_denied",
            "0xc0000022", "no session")


def _enum(result):
    """Trustworthy count: a real number ONLY when findings were actually read;
    ``denied`` when the query was blocked, ``0`` when it ran but found nothing.
    """
    if result is None:
        return None
    try:
        status = result.status
    except (Exception, SystemExit):
        return "denied"
    if getattr(result, "kind", "typed") == "captured":
        if any(m in _messages(result).lower() for m in _BLOCKED):
            return "denied"
        records = getattr(getattr(result, "data", None), "records", None)
        return len(records) if isinstance(records, list) else "ran"
    if status is ResultStatus.SUCCESS:
        return _count_fields(result)
    return 0 if status is ResultStatus.NEGATIVE else "denied"


def _messages(modresult):
    """Flatten every log message a module/action emitted into one string."""
    out = []
    results = getattr(modresult, "results", None) or [modresult]
    for r in results:
        out.extend(getattr(ev, "message", str(ev)) for ev in getattr(r, "events", None) or [])
        data = getattr(r, "data", None)
        out.extend(getattr(ev, "message", str(ev)) for ev in getattr(data, "events", None) or [])
    return " | ".join(m for m in out if m)


_NEG = ("not vulnerable", "probably patched", "not affected", "is not vuln")
_CANT = ("access denied", "requires a username", "requires a ", "failed to bind",
         "connection reset", "error connecting", "unexpected exception", "something went wrong",
         "successful bind must be completed", "no ldap entries", "cannot connect", "no session")


def _vuln_status(modresult):
    """Tri-state from a detection module's output, robust to mixed/partial results:
    VULNERABLE (>=1 method vulnerable) > could-not-run (blocked/errored) > safe.
    """
    low = _messages(modresult).lower()
    if not low:
        return "ran/unclear"
    # Strip the negative phrases so a "not vulnerable to X" can't look like a hit.
    stripped = low
    for phrase in _NEG:
        stripped = stripped.replace(phrase, "")
    if "vulnerable" in stripped:
        return "VULNERABLE"
    if any(k in low for k in _CANT):
        return "could-not-run"
    if any(k in low for k in _NEG):
        return "safe"
    return "ran/unclear"


def _safe_open(host, protocol, ident, pr):
    """Open a protocol session for one identity, or record why it could not."""
    try:
        session = getattr(host, protocol)(**ident)
    except (Exception, SystemExit) as e:
        pr.errors.append(f"connect: {type(e).__name__}: {e}")
        return None
    data = getattr(getattr(session, "result", None), "data", None)
    pr.reachable = bool(getattr(session, "ok", False)) or bool(getattr(data, "connected", False))
    pr.authenticated = bool(getattr(session, "authenticated", False))
    pr.guest = bool(getattr(data, "guest", False))
    pr.admin = getattr(session, "admin", None)
    pr.signing_required = getattr(data, "signing_required", None)
    pr.channel_binding = getattr(data, "channel_binding", None)
    return session if getattr(session, "ok", False) else None


# --------------------------------------------------------------------------- #
# per-protocol sweeps
# --------------------------------------------------------------------------- #
def sweep_smb(host, ident):
    pr = ProtoResult("smb")
    smb = _safe_open(host, "smb", ident, pr)
    if smb is None:
        return pr

    def shares():
        r = smb.shares()
        if not r.ok:
            return "denied" if r.status is not ResultStatus.NEGATIVE else {"total": 0}
        rec = r.data.shares
        return {
            "total": len(rec),
            "readable": [s.name for s in rec if "READ" in s.access],
            "writable": [s.name for s in rec if "WRITE" in s.access],
        }
    info = _try(pr, "shares", shares)

    # Spider + download everything this identity can read.
    if isinstance(info, dict) and info.get("readable"):
        _try(pr, "spidered", lambda: {"ran": smb.module("spider_plus", download_flag=True, max_file_size=SPIDER_MAX).ok})

    def passpol():
        r = smb.pass_pol()
        return r.data.min_password_length if r.ok else "denied"

    _try(pr, "rid_brute_users", lambda: _enum(smb.rid_brute()))
    _try(pr, "pass_pol_min_len", passpol)
    _try(pr, "local_admins", lambda: _enum(smb.local_groups(local_groups="Administrators")))
    _try(pr, "disks", lambda: _enum(smb.disks()))
    _try(pr, "loggedon", lambda: _enum(smb.loggedon_users()))
    return pr


def sweep_ldap(host, ident, auth_mode):
    pr = ProtoResult("ldap")
    ldap = _safe_open(host, "ldap", ident, pr)
    if ldap is None:
        return pr

    _try(pr, "users", lambda: _enum(ldap.users()))
    _try(pr, "groups", lambda: _enum(ldap.groups()))
    _try(pr, "computers", lambda: _enum(ldap.computers()))
    _try(pr, "dcs", lambda: _enum(ldap.dc_list()))
    _try(pr, "ous", lambda: _enum(ldap.ous()))
    _try(pr, "asreproastable", lambda: _enum(ldap.asreproast()))
    _try(pr, "unconstrained_delegation", lambda: _enum(ldap.trusted_for_delegation()))
    _try(pr, "delegation_entries", lambda: _enum(ldap.find_delegation()))
    _try(pr, "password_not_required", lambda: _enum(ldap.password_not_required()))
    _try(pr, "admin_count", lambda: _enum(ldap.admin_count()))
    _try(pr, "gmsa", lambda: _enum(ldap.gmsa()))
    _try(pr, "machine_account_quota", lambda: (lambda m: m.data.quota if m.ok else "denied")(ldap.module("maq")))
    _try(pr, "adcs", lambda: _vuln_status(ldap.module("adcs")))
    _try(pr, "desc_with_secrets", lambda: _enum(ldap.module("get-desc-users")))
    if auth_mode:
        _try(pr, "kerberoastable", lambda: _enum(ldap.kerberoasting()))
        _try(pr, "laps_readable", lambda: (lambda m: "readable" if m.ok else "no")(ldap.module("laps")))
        _try(pr, "bloodhound_collected", lambda: (lambda m: "collected" if m.ok else "no (try --dns-server)")(ldap.bloodhound()))
    return pr


def sweep_mssql(host, ident, auth_mode):
    pr = ProtoResult("mssql")
    sql = _safe_open(host, "mssql", ident, pr)
    if sql is None:
        return pr

    def identity():
        r = sql.query(query="SELECT SUSER_SNAME() AS login, IS_SRVROLEMEMBER('sysadmin') AS sysadmin")
        return r.one() if r.ok else "denied"

    _try(pr, "identity", identity)
    _try(pr, "linked_servers", lambda: _enum(sql.module("enum_links")))
    _try(pr, "impersonation", lambda: _enum(sql.module("enum_impersonate")))
    if auth_mode:
        _try(pr, "mssql_priv", lambda: (lambda m: "ok" if m.ok else "no")(sql.module("mssql_priv")))
    return pr


def sweep_simple(host, protocol, ident, extra=None):
    """Reachability/auth probe for protocols without deep enumeration."""
    pr = ProtoResult(protocol)
    session = _safe_open(host, protocol, ident, pr)
    if session is not None and extra:
        extra(pr, session)
    return pr


def _ftp_extra(pr, ftp):
    _try(pr, "listing", lambda: "ok" if ftp.ls().ok else "denied")


def _ssh_extra(pr, ssh):
    _try(pr, "sudo", lambda: "ok" if ssh.sudo_check().ok else "no")


def _nfs_extra(pr, nfs):
    _try(pr, "exports", lambda: _enum(nfs.enum_shares()))


def sweep_vulns(host, ident):
    """Host-level detection-only checks; returns (status_map, raw_message_map)."""
    statuses, details = {}, {}
    pr = ProtoResult("smb")
    smb = _safe_open(host, "smb", ident, pr)
    # ms17-010 can reset the SMB connection, so run it last.
    for mod in ("zerologon", "nopac", "printnightmare", "smbghost", "coerce_plus", "ms17-010"):
        try:
            if smb is None:
                statuses[mod] = "unreachable"
                continue
            m = smb.module(mod)
            statuses[mod] = _vuln_status(m)
            details[mod] = _messages(m)[:600]
        except (Exception, SystemExit) as e:
            statuses[mod] = f"error:{type(e).__name__}"
    try:
        lpr = ProtoResult("ldap")
        ldap = _safe_open(host, "ldap", ident, lpr)
        if ldap is None:
            statuses["sccm"] = "unreachable"
        else:
            m = ldap.module("sccm")
            statuses["sccm"] = _vuln_status(m)
            details["sccm"] = _messages(m)[:600]
    except (Exception, SystemExit) as e:
        statuses["sccm"] = f"error:{type(e).__name__}"
    return statuses, details


# --------------------------------------------------------------------------- #
# checklist printer
# --------------------------------------------------------------------------- #
def _fmt_proto(pr):
    head = f"    {pr.protocol.upper():<6} reachable:{'Y' if pr.reachable else 'n'} auth:{'Y' if pr.authenticated else 'n'}"
    if pr.protocol in ("smb", "ldap"):
        head += f" admin:{pr.admin} signing:{pr.signing_required}"
    lines = [head]
    for key, value in pr.facts.items():
        lines.append(f"        - {key}: {value}")
    if pr.errors:
        lines.append(f"        (skipped: {len(pr.errors)} check(s) errored)")
    return "\n".join(lines)


def print_checklist(report):
    out = ["", "=" * 72, f" {report.target}   {CHECKLIST_TITLE}", "=" * 72]
    for ident in report.identities:
        out.append(f" IDENTITY: {ident.label}")
        reachable = [pr for pr in ident.protocols.values() if pr.reachable]
        if not reachable:
            out.append("    (no service reachable / nothing readable as this identity)")
        out.extend(_fmt_proto(pr) for pr in reachable)
    out.append(" VULN / INFRA (detection-only):")
    out.extend(f"    {k:<14} {v}" for k, v in report.vulns.items())
    out.append("=" * 72)
    print("\n".join(out))


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def run(host):
    host.defaults(stop_on_error=False)
    report = HostReport(target=host.target)

    for label, ident in IDENTITIES:
        ir = IdentityReport(label=label)
        ir.protocols["smb"] = sweep_smb(host, ident)
        ir.protocols["ldap"] = sweep_ldap(host, ident, AUTH_MODE)
        ir.protocols["mssql"] = sweep_mssql(host, ident, AUTH_MODE)
        ir.protocols["winrm"] = sweep_simple(host, "winrm", ident)
        ir.protocols["rdp"] = sweep_simple(host, "rdp", ident)
        ir.protocols["ssh"] = sweep_simple(host, "ssh", ident, _ssh_extra)
        ir.protocols["ftp"] = sweep_simple(host, "ftp", ident, _ftp_extra)
        ir.protocols["vnc"] = sweep_simple(host, "vnc", ident)
        ir.protocols["nfs"] = sweep_simple(host, "nfs", ident, _nfs_extra)
        report.identities.append(ir)

    report.vulns, report.vuln_detail = sweep_vulns(host, VULN_IDENT)
    report.any_access = any(pr.reachable and (pr.authenticated or pr.facts) for ir in report.identities for pr in ir.protocols.values())

    print_checklist(report)
    return host.finding(FINDING_NAME, ok=report.any_access, data=report, inputs={"identities": [label for label, _ in IDENTITIES]})
