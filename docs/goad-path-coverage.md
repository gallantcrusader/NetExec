# GOAD privileged-path coverage

Goal: Python playbooks for all paths to privileged users and tier-zero targets
in this deployed GOAD lab, with the NetExec changes needed to support them.
This is an implementation and evidence ledger, not a completion claim.

## Scope and evidence

Lab hosts are Kingslanding `10.60.0.10`, Winterfell `10.60.0.11`, Meereen
`10.60.0.12`, Castelblack `10.60.0.22`, and Braavos `10.60.0.23`.
The Parrot runner is VM 409 (`10.60.0.101`), tmux `netexec-playbooks`.
The three DCs are tier-zero targets. Privileged domain groups, accounts with
control over those groups/DCs, and certificate authorities must be included in
the eventual graph. SQL sysadmin is a distinct privilege; it alone does not
prove host administrator or domain/tier-zero control.

The initial source inventory is the deployed GOAD checkout's
`ad/GOAD/data/config.json`, `ad/GOAD/data/inventory`, and the scripts explicitly
enabled by that config. Source configuration describes intended scenarios;
live observations must establish which scenarios actually exist. Archived or
unreferenced scripts are not evidence of active lab configuration.

## Verified playbooks

| Playbook | Live evidence | Limit |
| --- | --- | --- |
| `examples/playbooks/smoke/lab_smoke.py` | Winterfell SMB/LDAP, shared sessions, database credential reuse, typed results, explicit continuation after anonymous-share denial | Does not prove default stop or privilege escalation |
| `examples/playbooks/verify/goad_sql_paths.py` | Jon Snow is SQL sysadmin on Castelblack; linked BRAAVOS login executes SELECT as `sa`, also sysadmin | Does not prove OS or AD control |
| `examples/playbooks/verify/goad_sql_impersonation.py` | Brandon → Jon and Samwell → sa on Castelblack; Jorah → sa on Braavos. All three changed sysadmin=0 to 1, then returned to the original identity/sysadmin=0, with a follow-up query on the same session | LOGIN impersonation only; combined linked-server chains remain |
| `examples/playbooks/verify/goad_sql_database_user.py` | Arya → master:dbo with database CONTROL=1/server CONTROL=0; Arya → msdb:dbo with database CONTROL=1/server CONTROL=1. Original identity and database restored after each; follow-up queries and shared-session identity checks passed | Does not prove Windows or AD privileges, or combined linked-server chains |
| `examples/playbooks/chains/goad_cross_host_sql.py` | Winterfell LDAP Jon credential reference reused on Castelblack MSSQL → SQL sysadmin there → configured Braavos link as sa/sysadmin. Six successful typed results and identity/session-reuse checks | SQL privileges only; no Windows or AD control claimed |
| `examples/playbooks/chains/goad_laps_path.py` | Meereen LDAP Jorah read Braavos's legacy LAPS password → local Administrator SMB login → saved SMB credential reference reused, both logins passed NetExec's admin check. AD publishes `ESSOS-CA` on Braavos; CA RPC and NTLM web enrollment were observed there. Eight successful typed results | Reaches a CA host's local administrator, but certificate issuance, CA configuration control, and domain privilege transitions were not attempted |
| `examples/playbooks/verify/goad_acl_inventory.py` | All 22 explicit ACL entries from the GOAD source config checked against live ordered DACLs: North 2/2, Sevenkingdoms 12/12, Essos 7/8. Thirteen user DACL assessments under explicit SID assumptions: 10 allowed, 3 unknown | Direct ACE presence and conditional DACL assessments only; no full Windows access check, group transitions, or directory writes proven |
| `examples/playbooks/chains/goad_khal_ca_path.py` | Khal authenticated to Meereen LDAP; his saved database credential authenticated as SMB administrator on Braavos. Live SAMR listed Khal in local Administrators, AD published ESSOS-CA on Braavos, and CA RPC plus NTLM web enrollment were observed. His direct ESC4 template ACE and conditional DACL allow were recorded | CA/template configuration and certificate issuance were not changed or attempted |
| `examples/playbooks/verify/goad_group_inventory.py` and `goad_group_reconcile.py` | All 46 source-configured directory membership edges matched live LDAP results across three domains. Three foreign-security-principal SIDs correlated to home-domain identities. Five candidate Domain Admin membership paths emerged | Directory graph and SID correlation do not prove an executable ACL transition or full Windows logon token |
| `examples/playbooks/verify/goad_privileged_membership.py` | AD `tokenGroups` contained the Domain Admins SID for all five candidate users: Eddard, Daenerys, Drogon, Cersei, Robert | Computed directory groups do not by themselves prove a successful privileged login to each endpoint |
| `examples/playbooks/verify/goad_local_group_inventory.py` | All 17 source-configured local Administrators and Remote Desktop Users edges matched live SAMR member SIDs on the five hosts | SAMR names are unqualified; two identities are not independently present in the 46-edge directory graph. Group membership alone does not test RDP or host logon |
| `examples/playbooks/verify/goad_host_reachability.py` | Offline join of saved LDAP and SAMR SID evidence found 35 observed host-alias members, including all 17 configured entries, and 53 candidate user-to-host-group routes | One shortest directory chain per user and observed alias member; alternate chains and endpoint logons remain untested |

September 27 artifacts are in the sibling workspace directory
`netexec-lab-results/2026-09-27`: `goad-smoke.json`, `goad-sql-jon.json`,
`goad-sql-brandon.json`, `goad-sql-samwell.json`, and `goad-sql-jorah.json`.
Arya's USER checks are in `goad-sql-arya.json`; the follow-up with explicit
effective server-control checks is `goad-sql-arya-control.json`.
The cross-host route is in `goad-cross-host-sql-verified.json`; its initial
named-instance prerequisite mismatch remains in `goad-cross-host-sql-prerequisite.json`.
The LAPS route and CA observations are in `goad-laps-ca-path.json`. The preceding
`goad-laps-path-initial.json` and `goad-laps-path-verified.json` retain the first
admin-check timeout and its successful follow-up. The admin check now records
`unknown` and an error for transport failures, rather than treating them as
an access denial.
Actual commands are recorded in `tests/e2e_commands.txt`.
The three ACL-inventory artifacts are `goad-acl-inventory-north.json`,
`goad-acl-inventory-essos.json`, and `goad-acl-inventory-sevenkingdoms.json`.
Their manifest is `examples/playbooks/goad_acl_manifest.json`, generated from
all 22 entries in the GOAD checkout's `ad/GOAD/data/config.json`; its SHA-256
identifies the source snapshot and no account secrets were copied into it.
The follow-up `goad-acl-inventory-{north,essos,sevenkingdoms}-assessed.json`
artifacts add computed directory SIDs for source-classified user principals.
They retain ten conditional allows and three `unknown` outcomes. Essos's two
unknowns require object/property-set semantics; the Sevenkingdoms unknown is
on AdminSDHolder where SELF cannot be resolved from an object SID. Each user
was expanded once per domain workflow; group, gMSA, and built-in anonymous
principals explicitly remain unassessed as complete access tokens.

The Khal CA-host route is `goad-khal-ca-path.json`. The three group inventory
artifacts are `goad-groups-{north,essos,sevenkingdoms}.json`; their offline
SID reconciliation is `goad-membership-graph.json`. The source membership
manifest has 46 directory and 17 host-local edges. The computed membership
artifacts are `goad-privileged-membership-{north,essos,sevenkingdoms}.json`,
each with a successful typed summary and no missing or failed user.
The five host-local artifacts are `goad-local-groups-{kingslanding,winterfell,meereen,castelblack,braavos}-verified.json`.
The initial Castelblack/Jorah and Braavos/Jorah SAMR reads were denied; those
are retained as `goad-local-groups-{castelblack,braavos}-initial-denied.json`.
SAMR returned bare member names and SIDs; 15 of the 17 configured members
also have matching SID/name/domain nodes in the 46-edge directory graph.
`DragonRider` and `greatmaster` have live local-group SIDs but no independent
node in that limited graph. The inventory avoids treating the bare name alone
as proof of a domain identity beyond the configured domain and observed SID.
The offline `goad-host-reachability.json` report joins the same saved artifacts
by SID. It includes extra live SAMR alias members outside the source config,
preserves the underlying result indices, and separates configured edges from
additional observations. Its 53 membership routes are candidates, not 53
successful privileged logins or a complete enumeration of alternate chains.

## Remaining coverage

`examples/playbooks/chains/goad_acl_chain.py` collected all eight expected direct ACE
links in the Sevenkingdoms chain on Kingslanding, using Tywin's login. The
`goad-acl-chain.json` artifact retains complete ordered descriptors, exact trustee
SIDs, masks, GUIDs, and match indices. Its final result explicitly says
`candidate_chain_present=true` and `transitions_executed=false`. This is live
configuration evidence, not an effective-access or executed-compromise claim.

The follow-up `goad-acl-assessment.json` contains 15 successful typed results:
the connection, eight descriptors, five computed user group expansions, and
the chain summary. All five user edges assessed as `allowed` under the recorded
directory SID and authenticated network-logon assumptions. The three group
edges explicitly remain unassessed pending preceding membership transitions.
Ordered allow/deny evaluation is a conditional DACL assessment; it does not
construct a complete Windows token or prove that a directory operation succeeds.
No directory transitions were executed. The native `token-groups` command was
also verified live for Tywin in the same tmux session.

The broad inventory reconciled the other configured direct ACL grants as well,
including Khal → the Essos `ESC4` certificate template in the Configuration
partition, Varys → Domain Admins and AdminSDHolder, Renly → Crownlands OU,
and AcrossTheNarrowSea → Kingslanding DC. Varys → Domain Admins is one of the
conditional DACL allows; it is not evidence that Varys changed group membership.
North's two Anonymous Logon rights
were both supplied by one live ACE with mask `0x20014`. Essos's configured
`gmsaDragon$ → drogon` GenericAll entry did **not** appear on Drogon's live
DACL: the gMSA SID and Drogon object resolved, but there was no ACE for that
SID. This is a source/live discrepancy, not a working privilege path. None of
these direct grants alone proves effective rights or an executed transition.

| Route family | Configuration evidence | Work still required |
| --- | --- | --- |
| Group membership and local/domain privilege | Domain users/groups, cross-domain group members, host local_groups | 46/46 directory and 17/17 configured local edges verified live; five Domain Admin paths confirmed with computed SIDs. Offline graph joins 35 live alias members to 53 candidate routes; enumerate alternate chains and verify endpoint access separately |
| Sevenkingdoms ACL chain | Tywin → Jaime → Joffrey → Tyron → Small Council → DragonStone → KingsGuard → Stannis → Kingslanding computer | Eight direct ACE links and five user group expansions collected live; five conditional DACL assessments allowed. Full-token effective rights, group traversal, and execution of the complete chain remain |
| Other Sevenkingdoms ACL paths | AcrossTheNarrowSea → Kingslanding; Varys → Domain Admins/AdminSDHolder; Renly → Crownlands OU | All four direct ACEs verified live. Conditional rights, group traversal, and downstream transitions remain |
| Essos ACL paths | Khal → Viserys/ESC4; Spys → Jorah; Viserys → Jorah; DragonsFriends → Braavos; Missandei → Khal/Viserys; gmsaDragon → Drogon | Seven of eight direct ACEs observed. gmsaDragon → Drogon absent live; validate conditional rights and chained paths without counting the missing edge |
| Password/secret discovery | Descriptions, open shares, SYSVOL files, autologon and stored credentials | Discover actual values, authenticate intentionally selected candidates, store successful references, connect to privilege graph |
| Kerberos service/preauthentication paths | User SPNs and enabled AS-REP/delegation scripts | Typed evidence, credential/ticket lifecycle, end-to-end playbooks |
| Delegation and computer-object control | Enabled constrained-delegation scripts and computer ACLs | Read prerequisites, validate target/service constraints, chain to configured privileged targets |
| GPO control | Enabled `gpo_abuse.ps1` | Live GPO ACL/link/target evidence and complete path |
| SQL impersonation | Brandon → Jon; Samwell → sa; Arya → dbo; Jorah → sa | Three LOGIN and two USER transitions/restoration verified live. Combinations with linked-server routes and downstream Windows/AD paths remain |
| SQL links | Castelblack ↔ Braavos configured login mappings | Forward Jon route verified; reverse route and upstream/downstream combinations remain |
| LAPS/gMSA | Essos laps_readers/gmsa and Braavos use_laps | Jorah → legacy LAPS read → Braavos local Administrator and stored-reference reuse verified live. Other readers, LAPS hosts, and gMSA chains remain |
| AD CS | Inventory CA hosts/custom templates, ESC4 ACL, host ESC6/10/11/13 settings | Braavos ESSOS-CA publication, CA RPC, and NTLM web enrollment observed on the LAPS and Khal administrator routes. Certificate templates/CA settings, issuance rights, and other CA paths remain |
| Trust/SID history | Domain trust config and enabled `sidhistory.ps1` | Live trust/filtering/SID evidence and cross-domain/forest paths |
| Session/service/web paths | RDP scheduler, stored credentials, IIS upload permissions, SQL service accounts | Verify current sessions/services and actual privilege transitions |
| Relay/name-resolution paths | Enabled NTLM relay/responder scripts and LLMNR/NBT-NS settings | Verify prerequisites and configured targets; scoped validation remains |

This table is an initial family inventory, not an exhaustive list of paths.
Completion requires a live graph, all applicable source scenarios reconciled
against it, executable playbooks for its privilege-reaching routes, and result
evidence for each route. Failures, missing prerequisites, and untested routes
must remain visible rather than being counted as successful coverage.

## Framework gaps

- Cross-host orchestration now supports `host.at(target)` with explicit CLI
  destinations, shared ordered evidence, database credential references, and
  per-target session reuse/cleanup. Each root target retains an independent
  workflow. The Winterfell → Castelblack → Braavos SQL route was verified live;
  general graph scheduling across independent root workflows remains.
- Semantic edge/path results with evidence provenance and explicit prerequisites.
- Typed coverage for remaining actions/modules used by these paths.
- Shared-session identity restoration for general impersonation chains. The
  bounded SQL LOGIN/USER observation module now verifies identity and database restoration, blocks reuse
  if restoration is unknown, and allows a new connection to replace that session.
- Ticket/certificate credential representation beyond password/hash rows.
- Resume/checkpoint support for long chains and clear incomplete-path reporting.

Playbook CLI domain and DNS defaults were added after the first live run exposed
the missing `-d` support. Explicit per-connection options override defaults;
stored credential references retain their original domains.
