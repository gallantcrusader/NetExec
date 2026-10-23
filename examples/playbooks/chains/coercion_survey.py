"""Coercion survey: the full authentication-coercion matrix for one host.

A focused, detection-first survey of every way a host can be made to authenticate
out (the first half of a coercion -> NTLM-relay chain), deeper than the coercion
bundle in ``ad_hardening_posture.py``:

  * SMB coercion vectors   — DFSCoerce / ShadowCoerce / PetitPotam / PrinterBug /
                             MSEven, each marked reachable or not.
  * MSSQL coercion vector  — whether the SQL service account can be coerced out
                             (ACTIVE; only tested when a listener is configured).
  * SMB signing            — reported as relay-risk *context*: a reachable
                             coercion vector only matters if a non-signing relay
                             target exists, and relay-to-SMB needs signing off.

The SMB survey is DETECTION-ONLY. It runs the ``coerce_plus`` module with NO
listener, so the module merely binds the coercion RPC interfaces and logs
``VULNERABLE, <Method>`` for each reachable vector — it never fires a coercion and
sets up no relay. ``coerce_plus`` is the only live SMB coercion module; the old
``petitpotam`` / ``dfscoerce`` / ``shadowcoerce`` / ``printerbug`` / ``efsr_spray``
modules were retired and are not used.

The MSSQL vector is different: ``mssql_coerce`` has no detection mode — it executes
``xp_dirtree``/``xp_fileexist``-style calls to make the SQL service authenticate out
to a listener. So it is ACTIVE and only runs when ``NXC_COERCE_LISTENER`` is set;
without it the MSSQL vector is reported as "not tested".

    # detection-only SMB coercion matrix (+ signing context)
    nxc playbook <host> examples/playbooks/chains/coercion_survey.py -u USER -p PASS -d DOMAIN

    # also actively test the MSSQL coercion vector against an attacker listener
    NXC_COERCE_LISTENER=10.10.10.5 \
        nxc playbook <host> examples/playbooks/chains/coercion_survey.py -u USER -p PASS -d DOMAIN

A per-host summary is printed; the full typed ``CoercionSurvey`` is saved under
NXC_PATH. Target-agnostic — point it at any DC or member host.
"""

import os
from dataclasses import dataclass, field

# Vectors coerce_plus probes with METHOD=all, in the order it reports them. Each is
# logged as a highlight line "VULNERABLE, <Method>" when the interface answers.
COERCION_METHODS = ("DFSCoerce", "ShadowCoerce", "PetitPotam", "PrinterBug", "MSEven")


@dataclass
class CoercionSurvey:
    target: str
    smb_reachable: bool = False
    smb_authenticated: bool = False
    smb_signing_required: bool | None = None
    smb_coercion_assessed: bool = False
    smb_vectors: dict = field(default_factory=dict)  # method -> True when the interface answered
    mssql_reachable: bool = False
    mssql_coerce_attempted: bool = False
    mssql_coerce_ok: bool | None = None
    mssql_note: str | None = None
    relay_to_smb_viable: bool = False
    exposed: bool = False
    reason: str | None = None
    evidence_indices: list = field(default_factory=list)


def _env(name, default=None):
    value = os.environ.get(name, "").strip()
    return value or default


def _open(host, protocol, **options):
    """Open a protocol session, swallowing even SystemExit so one dead or odd
    protocol (or a stale protocol DB that calls exit()) can never abort the run.
    """
    try:
        return getattr(host, protocol)(**options)
    except (Exception, SystemExit):
        return None


def _coercion_hits(modresult):
    """SMB coercion vectors coerce_plus flagged, parsed from its highlight events.

    coerce_plus has no typed result contract, so the detection verdict only lives
    in its log output ("VULNERABLE, <Method>"). Parse those lines regardless of the
    captured result status (per-method errors log at error level and mark the
    result FAILED even when some interfaces answered).
    """
    hits = {}
    for event in getattr(modresult, "events", []):
        message = (event.message or "").strip()
        if message.upper().startswith("VULNERABLE,"):
            name = message.split(",", 1)[1].strip()
            match = next((m for m in COERCION_METHODS if m.casefold() == name.casefold()), name)
            hits[match] = True
    return hits


def _print_summary(data):
    """Print a compact operator-facing coercion summary."""
    lines = ["", "=" * 68, f" {data.target}   COERCION SURVEY", "=" * 68]
    if data.smb_reachable and data.smb_signing_required is not None:
        sig = "required" if data.smb_signing_required else "NOT REQUIRED"
    else:
        sig = "unknown"
    lines.append(f"  SMB    reachable:{'Y' if data.smb_reachable else 'n'} auth:{'Y' if data.smb_authenticated else 'n'} signing:{sig}")
    if data.smb_coercion_assessed:
        answered = [m for m, hit in data.smb_vectors.items() if hit] or ["none"]
        lines.append(f"  SMB coercion (detection, no listener): {', '.join(answered)}")
    else:
        lines.append("  SMB coercion not assessed (needs an authenticated SMB session)")
    if data.mssql_coerce_attempted:
        lines.append(f"  MSSQL coercion (ACTIVE, fired at listener): {'ok' if data.mssql_coerce_ok else 'did not run'}")
    else:
        lines.append(f"  MSSQL coercion not tested ({data.mssql_note})")
    lines.append("-" * 68)
    if data.relay_to_smb_viable:
        lines.append("  RELAY RISK: SMB signing off + a coercion vector reachable -> relay-to-SMB is viable")
    lines.append(f"  VERDICT: {'EXPOSED' if data.exposed else 'no coercion vector confirmed'}")
    lines.append("=" * 68)
    print("\n".join(lines), flush=True)


def run(host):
    host.defaults(stop_on_error=False)
    listener = _env("NXC_COERCE_LISTENER")
    data = CoercionSurvey(target=host.target)

    with host.evidence() as ev:

        def finish(reason=None):
            data.reason = reason
            data.evidence_indices = list(ev.indices)
            _print_summary(data)
            return host.finding(
                "coercion_survey",
                ok=data.exposed,
                data=data,
                inputs={"listener_set": bool(listener), "smb_coercion_assessed": data.smb_coercion_assessed, "mssql_coerce_attempted": data.mssql_coerce_attempted, "evidence": ev.indices},
            )

        # Step 1 — SMB relay context: reachability, auth, and the signing gate.
        smb = _open(host, "smb")
        if smb is not None:
            smb_conn = getattr(getattr(smb, "result", None), "data", None)
            data.smb_reachable = bool(getattr(smb_conn, "connected", False)) or bool(getattr(smb, "ok", False))
            data.smb_authenticated = bool(getattr(smb, "authenticated", False))
            data.smb_signing_required = getattr(smb_conn, "signing_required", None)

        # Step 2 — SMB coercion matrix: authenticated RPC interface binds, NO
        # listener, so no coercion is triggered and no relay is set up.
        if smb is not None and smb.authenticated:
            coerce = smb.module("coerce_plus", stop_on_error=False)
            data.smb_vectors = dict.fromkeys(COERCION_METHODS, False)
            data.smb_vectors.update(_coercion_hits(coerce))
            data.smb_coercion_assessed = True

        # Step 3 — MSSQL coercion vector. mssql_coerce is ACTIVE (it makes the SQL
        # service authenticate out) and has no detection mode, so it only runs when
        # a listener is explicitly configured.
        sql = _open(host, "mssql")
        if sql is not None:
            sql_conn = getattr(getattr(sql, "result", None), "data", None)
            data.mssql_reachable = bool(getattr(sql_conn, "connected", False)) or bool(getattr(sql, "ok", False))
        if not listener:
            data.mssql_note = "set NXC_COERCE_LISTENER to actively test; mssql_coerce has no detection mode"
        elif sql is None or not data.mssql_reachable:
            data.mssql_note = "MSSQL not reachable"
        elif not sql.authenticated:
            data.mssql_note = "MSSQL authentication not established"
        else:
            coerce_sql = sql.module("mssql_coerce", listener=listener, stop_on_error=False)
            data.mssql_coerce_attempted = True
            data.mssql_coerce_ok = bool(getattr(coerce_sql, "ok", False))
            data.mssql_note = f"ACTIVE: fired coercion calls at {listener}"

        # Step 4 — overall exposure + relay-risk note.
        smb_vector_reachable = any(data.smb_vectors.values())
        data.exposed = smb_vector_reachable or bool(data.mssql_coerce_attempted and data.mssql_coerce_ok)
        data.relay_to_smb_viable = smb_vector_reachable and data.smb_signing_required is False

        reason = None
        if not data.smb_coercion_assessed and not data.mssql_coerce_attempted:
            reason = "no coercion vector assessed (SMB auth needed for detection; set NXC_COERCE_LISTENER for the active MSSQL vector)"
        return finish(reason)
