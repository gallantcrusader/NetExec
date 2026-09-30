# NetExec Python playbooks — examples

A playbook is a Python file that defines `run(host)`; NetExec calls it once per
target. See [`docs/playbooks.md`](../../docs/playbooks.md) for the API reference
and the per-chain cookbooks in [`docs/cookbooks/`](../../docs/cookbooks).

Run one with:

```
nxc playbook <target> <path-to-playbook> -u USER -p PASS -d DOMAIN [--allow-target HOST ...]
```

## Layout

- **`teaching/<protocol>/`** — small, single-concept examples to learn the API,
  split by protocol and then by concept. Each file demonstrates exactly one idea.
  - `teaching/smb/` — `anonymous_enum`, `credentialed_shares`, `run_module`
  - `teaching/ldap/` — `authenticated_query`, `anonymous_users`, `run_module`
  - `teaching/mssql/` — `query_rows`, `linked_servers`
  - `teaching/patterns/` — cross-cutting patterns: `stop_on_error_defaults`,
    `evidence_and_finding`, `cross_host_credential_reuse`
- **`chains/`** — full, multi-step attack chains against the GOAD lab. Each has a
  one-page cookbook in [`docs/cookbooks/`](../../docs/cookbooks):
  - `goad_cross_host_sql.py` → [cross-host-sql](../../docs/cookbooks/cross-host-sql.md)
  - `goad_laps_path.py` → [laps-to-local-admin](../../docs/cookbooks/laps-to-local-admin.md)
  - `goad_khal_ca_path.py` → [adcs-esc4-ca-path](../../docs/cookbooks/adcs-esc4-ca-path.md)
  - `goad_acl_chain.py` → [acl-escalation-chain](../../docs/cookbooks/acl-escalation-chain.md)
- **`verify/`** — reconciliation / inventory playbooks that check the deployed
  GOAD configuration against live state (ACLs, group membership, LAPS, SQL
  impersonation, ADCS, offline graph joins). Their JSON manifests live beside
  them (loaded via `Path(__file__).with_name(...)`).
- **`smoke/`** — quick read-only smoke tests: `lab_smoke.py`, `recon.py`.

## The P0 API in one screen

```python
def run(host):
    host.defaults(stop_on_error=False)              # probe-style default; a per-call value always wins

    smb = host.smb()                                # -> ProtocolSession (cached per protocol+auth)
    if not smb.authenticated:                       # real, non-anon/guest login?
        return host.finding("example", ok=False)
    cred = smb.credential                           # CredentialRef to reuse; smb.admin is True/False/None

    shares = smb.shares()                           # -> ActionResult; shares.ok, shares.data.shares
    rows = host.ldap(credential=cred).query(        # tabular actions expose .rows / .one()
        query=["(objectClass=user)", "sAMAccountName"]).rows

    m = host.ldap(credential=cred).module("maq")    # modules -> ModuleResult (iterable + single-result proxy)
    quota = m.data.quota if m.ok else None

    with host.evidence() as ev:                     # ev.indices auto-collects each step's index
        host.at("10.60.0.22").smb(credential=cred).shares()   # host.at(target) needs --allow-target
    host.finding("example", ok=True, inputs={"users": len(rows), "evidence": ev.indices})
```
