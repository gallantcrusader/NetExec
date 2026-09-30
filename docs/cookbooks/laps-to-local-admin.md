# LAPS read to local admin

## Goal

Show that a delegated LAPS *reader* can turn a directory read into hands-on local administrator on a member server it was never given an account on. Starting as Jorah — a configured LAPS reader — on the Essos DC, the playbook reads the LAPS-managed password for `BRAAVOS$` out of the directory, uses it to log in locally to Braavos as the built-in `Administrator`, confirms that login lands as local admin, replays the *stored* credential to prove the session is reusable, and pauses to enumerate any AD CS surface that shares Braavos' hostname. The chain is read-only: it reads a password and authenticates with it; it rotates nothing, creates no service, and writes nothing back to the directory.

## Target and roles

- **Starting target (must be exactly this):** `10.60.0.12` — Meereen, the `essos.local` DC. `run(host)` raises `ValueError` if `host.target` is anything else.
- **`--allow-target` hosts:** `10.60.0.23` (Braavos, the member server whose LAPS password is read and used). It is reached with `host.at("10.60.0.23")`, which only succeeds if the host is allow-listed.
- **Run as:** `jorah.mormont` / `H0nnor!` in domain `essos.local` — a delegated LAPS reader (not a domain admin, and not a local user on Braavos).

## Command

```
nxc playbook 10.60.0.12 examples/playbooks/chains/goad_laps_path.py \
    -u jorah.mormont -p 'H0nnor!' -d essos.local \
    --allow-target 10.60.0.23
```

## Walkthrough (each step maps to the code)

All steps run inside `with host.evidence() as ev:` so every recorded action's index is auto-collected into `ev.indices` (the code's `LAPSPathEvidence.evidence_indices`).

1. **Resolve the pivot (no I/O yet).** `braavos = host.at("10.60.0.23")` mints a cross-host handle; `at()` connects nothing and only checks the target is allow-listed.
2. **Directory authentication as the reader.** `ldap = host.ldap()` opens an LDAP `ProtocolSession` on Meereen using the CLI `-u/-p/-d`. The run continues only if `ldap.ok` and `ldap.authenticated` (a real, non-anonymous login); `ldap.credential` is saved as `data.reader_credential`. Otherwise it ends NEGATIVE.
3. **Read the LAPS password.** `ldap.module("laps", computer="BRAAVOS")` returns a `ModuleResult`; the code scans `.data.computers` for exactly one row whose computer is `BRAAVOS$` with a non-null password. Not exactly one → NEGATIVE. It records `data.computer`, `data.password_source`, and `data.local_username` — `password.username or "Administrator"`, since legacy LAPS carries no account-name field and this lab uses the built-in Administrator.
4. **Note the AD CS surface (read-only).** `ldap.module("adcs")` returns published CA services; the code keeps into `data.published_ca_services` any whose `dNSHostName` matches Braavos' hostname. This is observation only and never gates the verdict.
5. **Log in locally with the read password.** `braavos.smb(username=data.local_username, password=…, local_auth=True)` opens an SMB `ProtocolSession` against Braavos. `data.authenticated = smb.ok and smb.authenticated`; if that fails → NEGATIVE. Then `data.admin_privileges = smb.admin` and `data.local_credential = smb.credential` (the code raises if a successful login yields no `CredentialRef`).
6. **Replay the stored credential.** `braavos.smb(credential=data.local_credential, local_auth=True)` reuses the cached local login instead of re-supplying the password; `data.reference_authenticated`/`data.reference_admin_privileges` come from `reused.ok/authenticated` and `reused.admin`. On success it also calls `reused.shares()` and `reused.module("enum_ca", stop_on_error=False)` — the per-call `stop_on_error=False` keeps a missing AD CS RPC path from aborting the probe — and, when that module returns SUCCESS/NEGATIVE, records `data.adcs_rpc_observed = ca.data.adcs_found`. It asserts the second `braavos.smb(...)` handle **is** the same cached session.
7. **Decide.** `data.reached = data.reference_authenticated and data.reference_admin_privileges is True` — reached only when the *reused* credential is both a working login and confirmed local admin.

## Expected structured verdict

The single finding is emitted by:

```
host.finding("goad_laps_path", ok=data.reached, data=data,
             inputs={"destination": "10.60.0.23", "legacy_laps_username": "Administrator"})
```

- **SUCCESS** (`ok=True`) when the replayed LAPS credential is confirmed local admin on Braavos. `data` (a `LAPSPathEvidence` dataclass) records: `reader_credential` and `local_credential` (reusable `CredentialRef`s), `computer` (`BRAAVOS$`), `password_source`, `local_username` (`Administrator`), `authenticated=True`, `admin_privileges=True`, `reference_authenticated=True`, `reference_admin_privileges=True`, `published_ca_services` and `adcs_rpc_observed` (the read-only AD CS notes; `adcs_rpc_observed` may be `None` if the RPC path is unavailable), `evidence_indices`, `reached=True`, and `reason=None`.
- **NEGATIVE** (`ok=False`) — a "reachable but not this" outcome — at the first failed precondition, carrying the fields populated so far and a `reason` string such as `"Directory reader authentication was not established"`, `"Exactly one readable Braavos LAPS password was not returned"`, `"Retrieved LAPS password did not establish a local SMB login"`, or `"NetExec's SMB admin check was not successful with the stored credential"`.

## Safety note

The privilege actually reached is **local `Administrator` on Braavos (10.60.0.23)** — one member server, via its LAPS-managed built-in account — and nothing more; it does **not** grant domain admin, control of `essos.local`, or admin on any other host, and every AD CS step is read-only enumeration, not exploitation.

> Lab status: this chain touches only LDAP and SMB, so it runs live once LAPS is deployed and `jorah.mormont` is delegated read on Braavos' password. The `enum_ca` RPC step is best-effort (`stop_on_error=False`) and simply leaves `adcs_rpc_observed=None` if AD CS RPC is not reachable.
