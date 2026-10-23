"""AD hardening-posture report: signing, channel binding, and coercion exposure.

Run against a domain controller (or any host) to produce a single typed verdict
describing the controls that gate NTLM relay:

  * SMB signing required?            (relay-to-SMB gate)
  * LDAP signing enforced?           (relay-to-LDAP gate)
  * LDAP channel binding (EPA)?      (relay-to-LDAPS gate; "Always" is hardened)
  * MSSQL channel binding enforced?  (relay-to-MSSQL gate, when TLS is in use)
  * Which coercion vectors answer?   (PetitPotam / DFSCoerce / ShadowCoerce /
                                      PrinterBug / MSEven)

The signing and channel-binding facts are read straight off NetExec's connection
(no extra traffic beyond opening each session). Coercion exposure is assessed with
the ``coerce_plus`` module with NO listener set, so it only performs authenticated
RPC interface binds to decide "reachable/vulnerable" — it never triggers a
coercion to an attacker host and sets up no relay. Nothing is exploited.

Works unauthenticated (SMB/LDAP signing + LDAP CB are observable without a login)
and reports more with a credential (MSSQL CBT and coercion need authentication):

    nxc playbook <dc> examples/playbooks/chains/ad_hardening_posture.py
    nxc playbook <dc> examples/playbooks/chains/ad_hardening_posture.py -u USER -p PASS -d DOMAIN
    nxc playbook <dc> examples/playbooks/chains/ad_hardening_posture.py -u USER -H NTHASH -d DOMAIN

A per-host summary is printed; the full typed result is saved under NXC_PATH.
"""

from dataclasses import dataclass, field

# Methods coerce_plus probes with METHOD=all, in the order it reports them. Each
# is logged as a highlight line "VULNERABLE, <Method>" when the interface answers.
COERCION_METHODS = ("DFSCoerce", "ShadowCoerce", "PetitPotam", "PrinterBug", "MSEven")


@dataclass
class ProtocolPosture:
    protocol: str
    reachable: bool = False
    authenticated: bool = False
    signing_required: bool | None = None
    channel_binding: str | None = None
    note: str | None = None


@dataclass
class HardeningPosture:
    target: str
    smb: ProtocolPosture | None = None
    ldap: ProtocolPosture | None = None
    mssql: ProtocolPosture | None = None
    coercion_assessed: bool = False
    coercion: dict = field(default_factory=dict)  # method -> True when the interface answered
    weaknesses: list[str] = field(default_factory=list)
    hardened: bool = False
    evidence_indices: list[int] = field(default_factory=list)


def _open(host, protocol, **options):
    """Open a protocol session, swallowing even SystemExit so one protocol (or a
    stale protocol DB that calls exit()) can never abort the whole report.
    """
    try:
        return getattr(host, protocol)(**options)
    except (Exception, SystemExit):
        return None


def _posture(protocol, session):
    """Fold a connect() result into a ProtocolPosture for one protocol."""
    pr = ProtocolPosture(protocol)
    if session is None:
        pr.note = "could not open a session"
        return pr
    data = getattr(getattr(session, "result", None), "data", None)
    if data is None:
        pr.note = "no connection result"
        return pr
    pr.reachable = bool(getattr(data, "connected", False)) or bool(getattr(session, "ok", False))
    pr.authenticated = bool(getattr(session, "authenticated", False))
    pr.signing_required = getattr(data, "signing_required", None)
    pr.channel_binding = getattr(data, "channel_binding", None)
    return pr


def _coercion_hits(modresult):
    """Methods coerce_plus flagged, parsed from its highlight events.

    coerce_plus has no typed result contract yet, so the detection verdict only
    lives in its log output ("VULNERABLE, <Method>"). Parse those lines rather
    than the result status (per-method errors mark the captured result FAILED).
    """
    hits = {}
    for event in getattr(modresult, "events", []):
        message = (event.message or "").strip()
        if message.upper().startswith("VULNERABLE,"):
            name = message.split(",", 1)[1].strip()
            match = next((m for m in COERCION_METHODS if m.casefold() == name.casefold()), name)
            hits[match] = True
    return hits


def _assess(data):
    """Derive the weakness list and the overall hardened verdict."""
    weak = data.weaknesses
    smb, ldap, mssql = data.smb, data.ldap, data.mssql
    # Signing/CB are only meaningful once the transport actually opened, so gate
    # every check on reachability — an unreachable host is "unknown", not "weak".
    smb_up = bool(smb and smb.reachable)
    ldap_up = bool(ldap and ldap.reachable)

    if smb_up and smb.signing_required is False:
        weak.append("SMB signing not required — NTLM relay to SMB is possible")
    if ldap_up and ldap.signing_required is False:
        weak.append("LDAP signing not enforced — NTLM relay to LDAP is possible")
    if ldap_up and ldap.channel_binding is not None and ldap.channel_binding not in ("Always",):
        weak.append(f"LDAP channel binding = {ldap.channel_binding!r} — relay to LDAPS is possible")
    if mssql and mssql.reachable and mssql.channel_binding == "not required":
        weak.append("MSSQL accepts an empty channel binding token — relay to MSSQL is possible")
    for method, hit in data.coercion.items():
        if hit:
            weak.append(f"Coercion interface reachable: {method}")

    # "hardened" needs positive confirmation of the SMB + LDAP gates, not just the
    # absence of flagged weaknesses (which an unreachable host would also satisfy).
    positives = (smb_up and smb.signing_required is True) and (ldap_up and ldap.signing_required is True) and (ldap_up and ldap.channel_binding == "Always")
    data.hardened = positives and not weak


def _print_summary(data):
    """Print a compact operator-facing posture summary."""
    lines = ["", "=" * 68, f" {data.target}   AD HARDENING POSTURE", "=" * 68]
    for pr in (data.smb, data.ldap, data.mssql):
        if pr is None:
            continue
        head = f"  {pr.protocol.upper():<6} reachable:{'Y' if pr.reachable else 'n'} auth:{'Y' if pr.authenticated else 'n'}"
        if pr.reachable and pr.signing_required is not None:
            head += f" signing:{'required' if pr.signing_required else 'NOT REQUIRED'}"
        if pr.reachable and pr.channel_binding is not None:
            head += f" channel-binding:{pr.channel_binding}"
        lines.append(head)
        if pr.note:
            lines.append(f"         ({pr.note})")
    if data.coercion_assessed:
        answered = [m for m, hit in data.coercion.items() if hit] or ["none"]
        lines.append(f"  COERCE reachable: {', '.join(answered)}")
    else:
        lines.append("  COERCE not assessed (needs an authenticated SMB session)")
    lines.append("-" * 68)
    if data.hardened:
        lines.append("  VERDICT: hardened against the relay paths checked")
    else:
        lines.append(f"  VERDICT: {len(data.weaknesses)} weakness(es)")
        lines.extend(f"    - {w}" for w in data.weaknesses)
    lines.append("=" * 68)
    print("\n".join(lines), flush=True)


def run(host):
    host.defaults(stop_on_error=False)
    data = HardeningPosture(target=host.target)

    with host.evidence() as ev:
        # SMB + LDAP signing/CB are observable from the connection itself; the
        # session is opened with whatever credential (if any) was supplied.
        smb = _open(host, "smb")
        data.smb = _posture("smb", smb)

        ldap = _open(host, "ldap")
        data.ldap = _posture("ldap", ldap)

        # MSSQL channel binding only applies when the server negotiates TLS and a
        # Windows login is available; mssql_cbt reports a typed verdict.
        sql = _open(host, "mssql")
        data.mssql = _posture("mssql", sql)
        if sql is not None and sql.authenticated:
            cbt = sql.module("mssql_cbt", stop_on_error=False)
            cbt_data = getattr(cbt, "data", None) if cbt else None
            cbt_required = getattr(cbt_data, "cbt_required", None)
            if cbt_required is True:
                data.mssql.channel_binding = "required"
            elif cbt_required is False:
                data.mssql.channel_binding = "not required"
            else:
                data.mssql.note = getattr(cbt_data, "reason", None) or "channel binding not assessed"
        elif data.mssql.reachable:
            data.mssql.note = "authentication required to assess channel binding"

        # Coercion exposure: authenticated RPC interface probe, NO listener, so no
        # coercion is triggered and no relay is set up.
        if smb is not None and smb.authenticated:
            coerce = smb.module("coerce_plus", stop_on_error=False)
            data.coercion = dict.fromkeys(COERCION_METHODS, False)
            data.coercion.update(_coercion_hits(coerce))
            data.coercion_assessed = True

    _assess(data)
    data.evidence_indices = list(ev.indices)
    _print_summary(data)
    return host.finding(
        "ad_hardening_posture",
        ok=data.hardened,
        data=data,
        inputs={"weaknesses": len(data.weaknesses), "coercion_assessed": data.coercion_assessed, "evidence": ev.indices},
    )
