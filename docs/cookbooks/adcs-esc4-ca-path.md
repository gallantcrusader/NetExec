# ADCS ESC4 certificate-template path to the CA host

## Goal

Verify — without changing anything — the two routes a low-privileged Essos user (Khal Drogo) has toward the Braavos certificate-authority host. It confirms whether Khal holds write-class rights over the `ESC4` certificate template's DACL (the misconfiguration that would let a template be rewritten into an escalation vehicle) and, separately, whether Khal's credential is a local administrator on Braavos where the CA is published. The playbook is read-only: it reads directory ACLs, group membership, published-CA metadata, local-group membership and CA RPC/web-enrollment surface. It rewrites no template, requests no certificate, and changes no AD, CA, or host configuration.

## Target and roles

- **Starting target (must be exactly this):** `10.60.0.12` — Meereen, the `essos.local` DC. `run(host)` raises `ValueError` if `host.target` is anything else, and again if the authenticated identity is not `khal.drogo`.
- **`--allow-target` hosts:** `10.60.0.23` (Braavos, the CA host). It is reached with `host.at("10.60.0.23")`, which only succeeds when the host is allow-listed.
- **Run as:** `khal.drogo` / `horse` in domain `essos.local` — an ordinary domain user (a Dothraki member), not a domain or enterprise admin.

## Command

```
nxc playbook 10.60.0.12 examples/playbooks/chains/goad_khal_ca_path.py \
    -u khal.drogo -p horse -d essos.local \
    --allow-target 10.60.0.23
```

## Walkthrough (each step maps to the code)

Every step appends its `host.run.results` index to `data.evidence_indices`, so the recorded verdict points back at the exact evidence it rests on.

1. **Resolve the pivot (no I/O yet).** `braavos = host.at("10.60.0.23")` mints a cross-host handle; `at()` connects nothing and only checks the target is allow-listed.
2. **Directory authentication as Khal.** `ldap = host.ldap()` opens an LDAP session on Meereen with the CLI `-u/-p/-d`. The run continues only when the login is real (`ldap.ok` and the connection authenticated); the identity must be `khal.drogo`, and `ldap.result.data.credential` is saved as `data.credential` for reuse. Otherwise it ends NEGATIVE.
3. **Compute Khal's effective SIDs.** `ldap.module("token-groups", principal="khal.drogo")` returns the transitive group SIDs into `data.directory_sids` — the identity set the DACL assessment is run against.
4. **Confirm the group precondition.** `ldap.groups(groups="Dothraki")` records whether Khal is actually a Dothraki member (`data.dothraki_member`).
5. **Read the ESC4 template DACL.** `ldap.module("daclread", target_dn="CN=ESC4,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local", ace_type="all")` returns the template's ordered ACEs. The code keeps the indices of *allowed* ACEs and runs `assess_dacl(...)` from `nxc.playbooks.access` over Khal's SIDs (plus Everyone `S-1-1-0`, Authenticated Users `S-1-5-11`, Self `S-1-5-2`) against the full-control mask `0xF01FF`. The result is candidate evidence of write-class control over the template — it does **not** modify the template.
6. **Note the published CA (read-only).** `ldap.module("adcs")` lists published CA services; the code keeps any whose `dNSHostName` is `braavos.essos.local` into `data.published_ca`.
7. **Authenticate to Braavos with Khal's credential.** `braavos.smb(credential=data.credential)` reuses the stored login against the CA host. If it does not authenticate → NEGATIVE. `data.braavos_admin` comes from the SMB admin check.
8. **Enumerate the local Administrators and CA surface.** `smb.local_groups(local_groups="Administrators", stop_on_error=False)` records the local-admin membership; `smb.module("enum_ca", stop_on_error=False)` records `data.ca_rpc_observed` and `data.web_enrollment_observed`. The per-call `stop_on_error=False` keeps a missing CA RPC path from aborting the probe.

## Verdict

The playbook records one `ActionResult` under protocol `playbook`, action `goad_khal_ca_path`, carrying the `KhalCAPath` dataclass (credential, directory SIDs, Dothraki membership, template ACE indices and `assess_dacl` outcome, published CA, Braavos admin flag, local administrators, CA RPC/web-enrollment observations, evidence indices).

- **SUCCESS** only when all three hold: `braavos_admin is True`, a Braavos CA publication was found, **and** the CA RPC endpoint was observed (`ca_rpc_observed is True`).
- **NEGATIVE** (branchable, not an error) at the first unmet precondition, with `data.reason` naming what was not verified.

## Safety note

SUCCESS means the *conditions* for the two routes were observed — write-class ACEs on the ESC4 template and/or local-admin + a reachable published CA on Braavos. It does **not** rewrite the template, enroll a certificate, or otherwise escalate; no privilege is actually exercised and nothing is changed.
