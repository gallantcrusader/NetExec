# RBCD takeover

`examples/playbooks/chains/rbcd_takeover.py` walks resource-based constrained
delegation end to end: confirm the grant, request an impersonated service ticket,
and verify it actually works — wiring the typed `rbcd` and `delegation` modules
into one verdict. (For the individual modules, see [rbcd](rbcd.md) and
[delegation](delegation.md).)

This is an **active** chain: it requests tickets from the KDC and authenticates to
the resource as the impersonated user, and — with `NXC_RBCD_WRITE=1` — writes the
delegation grant. Run it only where you are authorized to.

## The three steps

1. **`rbcd` (read)** — confirms the SOURCE account's SID is present in the TARGET
   computer's `msDS-AllowedToActOnBehalfOfOtherIdentity`. SUCCESS here means the
   KDC should honour an S4U2Proxy request from SOURCE to TARGET's services.
2. **`delegation` (S4U)** — authenticated as SOURCE, requests an S4U2Self+S4U2Proxy
   ticket impersonating a chosen user to TARGET's service, saving a ccache under
   `NXC_PATH/delegation/`.
3. **verify** — sets `KRB5CCNAME` to that ccache and opens SMB to the resource over
   Kerberos, reporting whether the impersonation grants access (and admin).

## Configuration

Point the playbook at the **DC** and pass the **resource host** to `--allow-target`.
All inputs come from the environment so the chain never fires by accident:

| Variable | Meaning |
| --- | --- |
| `NXC_RBCD_TARGET` | resource computer account, e.g. `WS02$` (required) |
| `NXC_RBCD_SOURCE` | delegating account you authenticate as, e.g. `WS01$` (required) |
| `NXC_RBCD_IMPERSONATE` | user to impersonate (default `Administrator`) |
| `NXC_RBCD_SPN` | explicit target SPN, e.g. `cifs/ws02.example.test` (optional) |
| `NXC_RBCD_VERIFY_HOST` | host to verify against over Kerberos (optional; `--allow-target`) |
| `NXC_RBCD_WRITE` | set to `1` to add the grant when it is absent (default off) |

```sh
export NXC_RBCD_TARGET='WS02$' NXC_RBCD_SOURCE='WS01$' NXC_RBCD_VERIFY_HOST=10.0.0.52
nxc playbook dc01.example.test examples/playbooks/chains/rbcd_takeover.py \
    -u 'WS01$' -H <nthash> -d example.test --allow-target 10.0.0.52
```

Authenticate as SOURCE with a password (`-p`), NT hash (`-H`), or Kerberos (`-k`) —
`delegation` reuses whichever secret the login used to request the S4U ticket. A
common way to obtain a controllable SOURCE computer account is the default machine
account quota (see the `maq` module and §5 of the playbook analysis).

## Result and caveats

The typed `rbcd_takeover` finding is `success` only when the delegated ticket
authenticates to the resource (or, with no `NXC_RBCD_VERIFY_HOST`, when the grant is
confirmed and a ticket is obtained). `data` carries the resolved `source_sid`,
`target_dn`, `target_spns`, the `ccache` path, its `expires_at`, and the verify
outcome.

- The `ccache` path is reported even when the automated verify cannot consume it
  (the S4U ccache holds a service ticket, not a TGT), so you can `export
  KRB5CCNAME=<path>` and continue with other Kerberos-aware tools. This handoff is
  the current workaround for NetExec not yet representing a ticket as a first-class
  reusable credential.
- An RBCD ACE is directory evidence; the KDC still decides whether to issue the
  delegated ticket, and service access depends on the impersonated user's rights.
- When the SPN cannot be chosen automatically, set `NXC_RBCD_SPN` to one of the
  SPNs the step-1 output lists for the target.
