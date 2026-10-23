"""BadSuccessor exposure: who can create a dMSA where — and can *you*?

BadSuccessor (Akamai, 2025) abuses a delegated Managed Service Account: a principal
that can create or control a ``msDS-DelegatedManagedServiceAccount`` in an OU can
make it "supersede" a target account and inherit the target's privileges, with only
create/write rights on the OU — no rights on the target. It requires a Windows
Server 2025 domain controller.

This chain is detection-only. It runs the typed ``badsuccessor`` module to find the
non-privileged principals with abusable OU control and whether a Server 2025 DC is
present, then uses ``token-groups`` to resolve the SIDs the *current* credential
holds and reports whether you personally are positioned to run the attack. It does
not create a dMSA or change the directory — staging the account is the active step,
left to dedicated tooling.

    nxc playbook <dc> examples/playbooks/chains/badsuccessor.py -u USER -p PASS -d DOMAIN

The finding is ``success`` only when a Server 2025 DC is present AND the current
principal holds an abusable OU right; otherwise it is ``negative`` and the data
still lists every abusable principal/OU found. A per-host summary is printed and
the full typed result is saved under NXC_PATH.
"""

from dataclasses import dataclass, field


@dataclass
class BadSuccessorPosture:
    target: str
    server_2025_present: bool = False
    server_2025_dcs: list[str] = field(default_factory=list)
    organizational_units: int = 0
    abusable_principals: list[dict] = field(default_factory=list)  # {name, sid, ous}
    current_principal: str | None = None
    current_sids: list[str] = field(default_factory=list)
    self_exploitable_ous: list[str] = field(default_factory=list)
    self_can_exploit: bool = False
    vulnerable: bool = False
    reached: bool = False
    reason: str | None = None
    evidence_indices: list[int] = field(default_factory=list)


def _print_summary(data):
    lines = ["", "=" * 68, f" {data.target}   BADSUCCESSOR EXPOSURE", "=" * 68]
    lines.append(f"  Server 2025 DC: {'yes' if data.server_2025_present else 'no (dMSA abuse not possible)'}")
    if data.server_2025_dcs:
        lines.append(f"    {', '.join(data.server_2025_dcs)}")
    lines.append(f"  OUs scanned: {data.organizational_units}")
    if data.abusable_principals:
        lines.append(f"  Non-privileged principals with abusable OU control: {len(data.abusable_principals)}")
        lines.extend(f"    - {p['name']} ({p['sid']}) -> {len(p['ous'])} OU(s)" for p in data.abusable_principals)
    else:
        lines.append("  No abusable OU control found")
    lines.append("-" * 68)
    if data.reached:
        lines.append(f"  VERDICT: current principal ({data.current_principal}) CAN run BadSuccessor")
        lines.extend(f"    via OU: {ou}" for ou in data.self_exploitable_ous)
    else:
        lines.append(f"  VERDICT: {data.reason}")
    lines.append("=" * 68)
    print("\n".join(lines), flush=True)


def run(host):
    host.defaults(stop_on_error=False)
    data = BadSuccessorPosture(target=host.target)

    with host.evidence() as ev:

        def finish(reason=None):
            data.reason = reason
            data.evidence_indices = list(ev.indices)
            _print_summary(data)
            return host.finding("badsuccessor", ok=data.reached, data=data, inputs={"vulnerable": data.vulnerable, "self_can_exploit": data.self_can_exploit, "evidence": ev.indices})

        ldap = host.ldap()
        if not ldap.authenticated:
            return finish("Directory authentication was not established")

        bs = ldap.module("badsuccessor")
        if bs.status is not None and str(bs.status) == "failed":
            return finish(bs.error or "badsuccessor enumeration failed")
        bd = bs.data
        data.server_2025_present = bool(getattr(bd, "server_2025_present", False))
        data.server_2025_dcs = list(getattr(bd, "server_2025_dcs", []) or [])
        data.organizational_units = int(getattr(bd, "organizational_units", 0) or 0)
        data.vulnerable = bool(getattr(bd, "vulnerable", False))
        for principal in getattr(bd, "principals", []) or []:
            data.abusable_principals.append({"name": principal.name, "sid": principal.sid, "ous": list(principal.ous)})

        # Resolve the SIDs the current credential holds, to decide whether *this*
        # identity is one of the abusable principals (not just someone in the domain).
        me = getattr(ldap.connection, "username", None)
        data.current_principal = me
        if me:
            groups = ldap.module("token-groups", principal=me)
            if groups.ok:
                data.current_sids = list(getattr(groups.data, "directory_sids", []) or [])
        held = set(data.current_sids)
        for principal in data.abusable_principals:
            if principal["sid"] in held:
                data.self_exploitable_ous.extend(principal["ous"])
        data.self_exploitable_ous = sorted(set(data.self_exploitable_ous))
        data.self_can_exploit = bool(data.self_exploitable_ous) and data.server_2025_present
        data.reached = data.self_can_exploit

        if data.reached:
            return finish(None)
        if not data.server_2025_present:
            return finish("No Server 2025 DC present — dMSA abuse is not possible")
        if data.abusable_principals:
            return finish("Abusable OU control exists, but not held by the current principal")
        return finish("No abusable OU control found")
