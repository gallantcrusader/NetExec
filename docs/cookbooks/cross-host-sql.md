# Cross-host SQL: follow a stored credential across a linked server

## Goal

Show that one directory login can be replayed into a database context and then hop one server further via a pre-configured MSSQL linked server. Starting from Jon's domain credential on the north DC, the playbook reuses that same login to authenticate to SQL on Castelblack, confirms it lands as SQL `sysadmin` there, discovers the configured `BRAAVOS` link, and runs an identity query *through* that link to prove the same sysadmin reach on a second, otherwise-unauthenticated SQL host. The whole chain is read-only: every SQL batch is a `SELECT`.

## Target and roles

- **Starting target (must be exactly this):** `10.60.0.11` — Winterfell, the `north.sevenkingdoms.local` DC. The playbook raises `ValueError` if `host.target` is anything else.
- **`--allow-target` hosts:** `10.60.0.22` (Castelblack, the SQL server) and `10.60.0.23` (Braavos, the linked SQL server). Both are reached with `host.at(...)`, which requires them to be allow-listed.
- **Run as:** `jon.snow` / `iknownothing` in domain `north.sevenkingdoms.local` (an unprivileged north domain user — no local admin, no DA).

## Command

```
nxc playbook 10.60.0.11 examples/playbooks/chains/goad_cross_host_sql.py \
    -u jon.snow -p iknownothing -d north.sevenkingdoms.local \
    --allow-target 10.60.0.22 --allow-target 10.60.0.23
```

## Walkthrough (each step maps to the code)

1. **Resolve pivot contexts (no I/O yet).** `castelblack = host.at("10.60.0.22")` and `braavos = host.at("10.60.0.23")` mint cross-host handles. `at()` performs no connection; it only checks the targets are allow-listed. All steps run inside `with host.evidence() as steps:` so every recorded action's index is auto-collected into `steps.indices`.
2. **Directory authentication.** `ldap = host.ldap()` opens an LDAP `ProtocolSession` on Winterfell using the CLI `-u/-p/-d`. The playbook checks `ldap.authenticated` (a real, non-anonymous login) and then grabs `ldap.credential` — the reusable `CredentialRef` stored as `data.source_credential`. Either check failing ends the run as a NEGATIVE verdict.
3. **Replay the credential into SQL.** `sql = castelblack.mssql(credential=data.source_credential)` opens an MSSQL `ProtocolSession` on Castelblack, reusing the LDAP login rather than re-supplying a password. `sql.authenticated` must hold; `sql.credential` is saved as `data.sql_credential`.
4. **Confirm local SQL sysadmin.** `sql.query(query=IDENTITY).one()` runs the identity `SELECT` and `.one()` returns the single result row as a dict. The run continues only if `machine_name == CASTELBLACK` and `is_sysadmin == 1`, recorded in `data.local_identity`.
5. **Enumerate linked servers.** `links = sql.module("enum_links")` returns a `ModuleResult`; the code scans `links.data.servers` for a row whose `SRV_NAME` is `BRAAVOS`. If the configured link is absent, it stops NEGATIVE.
6. **Query through the link.** `sql.module("exec_on_link", linked_server="BRAAVOS", command=IDENTITY).one()` runs the same identity `SELECT` on Braavos via the linked server and proxies the single row through `.one()` into `data.linked_identity`. `data.reached` is set true only when that remote row reports `machine_name == BRAAVOS` and `is_sysadmin == 1`.

## Expected structured verdict

The single finding is emitted by:

```
host.finding("goad_cross_host_sql", ok=data.reached, data=data,
             inputs={"sql_host": "10.60.0.22", "linked_host": "10.60.0.23"})
```

- **SUCCESS** (`ok=True`) when the linked query confirms sysadmin on Braavos. `data` (a `SQLPathEvidence` dataclass) records: `source_credential` and `sql_credential` (the reusable `CredentialRef`s), `local_identity` (the Castelblack identity row), `linked_identity` (the Braavos identity row), `evidence_indices` (the collected step indices), `reached=True`, `privilege="SQL sysadmin"`, and `reason=None`.
- **NEGATIVE** (`ok=False`) at the first failed precondition, with the populated fields so far and a `reason` string such as `"Stored credential did not establish SQL authentication on Castelblack"`, `"Castelblack SQL sysadmin prerequisite was not observed"`, `"Configured BRAAVOS SQL link was not found"`, or `"Linked query did not observe Braavos SQL sysadmin"`.

## Safety note

The privilege actually reached is **SQL `sysadmin`** on Castelblack and, through the link, on Braavos — nothing more. This does **not** establish Windows local administrator on either host or any domain control; `sysadmin` is a database-engine role, not an OS or directory privilege.

> Lab status: MSSQL (1433) is not currently listening in this GOAD lab, so a live run will end NEGATIVE at step 3 (SQL authentication on Castelblack). The chain above is the intended shape for when the SQL services are up.
