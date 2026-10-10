# getDomAdmin: credential-to-host traversal

`getDomAdmin.py` starts with no credential or one supplied credential and explores
credential/host states until it verifies administrator access to a domain controller,
exhausts its frontier, or reaches a configured budget. It runs once for the seed
target; `--allow-target` supplies every other host it may contact. Hosts learned
from LDAP or NetExec's database outside that list appear in the report but are not
contacted.

```sh
# From an anonymous start
nxc playbook DC_IP examples/playbooks/getDomAdmin.py \
  -d DOMAIN --dns-server DC_IP --allow-target SERVER_IP WORKSTATION_IP

# From a known credential
nxc playbook DC_IP examples/playbooks/getDomAdmin.py \
  -u USER -p PASSWORD -d DOMAIN --dns-server DC_IP \
  --allow-target SERVER_IP WORKSTATION_IP
```

The playbook classifies observed Windows hosts as domain controllers, servers,
or workstations using SMB and matching directory computer records. Each
credential/host pair is queued once. New credentials
discovered through NetExec output or its workspace database reopen the frontier,
so the same decision tree can be explored from the new identity. Observed DCs
are processed before servers, then workstations. The JSON report includes
`traversal_tree` for first-discovery parents, `access_edges` for successful
authentication, and `tier_zero_path` for the first verified path to a DC.
`relationship_edges` resolves NetExec's saved SMB admin and logged-on relation
IDs into principals and hosts. These are workspace candidates with explicit
`in_scope` markers; only an `adminTo` edge with a matching live SMB administrator
login receives `verified_in_run=true`. A saved `hasSession` relation alone does
not prove a current session or expand the target list.

Each in-scope SMB enumeration also consumes successful typed WKSSVC logged-on
user results and SAMR `Administrators` membership results. It adds current
`hasSession` and `localAdminMember` edges with `observed_in_run=true`, the
observing credential, the target, and the source RPC service. Failed or partial
results add no edge. These observations guide the graph; neither a session nor
group membership proves that the observing credential can authenticate as the
named principal or administer the target. Authentication and administrator
checks remain separate access edges.

`tier_zero_reached` requires an authenticated SMB session with administrator
privileges on an observed DC. `da_reached` adds a computed, same-domain Domain
Admins token-group membership check. A recovered `krbtgt` hash is recorded as
`tier_zero_material`; it is not counted as proof that DC access was established.

The first verified Tier Zero path stops the traversal by default. Set
`GETDA_STOP_ON_TIER_ZERO=0` to continue. `GETDA_MAX_STEPS` and
`GETDA_MAX_ROUNDS` bound the work. The run saves its result under `NXC_PATH`
unless `--results` names another path; a detailed log and JSONL event stream
are written under `NXC_PATH/logs`.

The decision tree currently attempts SMB enumeration, readable share downloads,
local-admin secret collection, LDAP inventory and roasting, SQL inventory, and
optional local cracking. Relay, poisoning, and ADCS exploitation are not launched
by this decision tree; relay candidate guidance is opt-in. An external tool being
present does not imply a specific escalation
technique succeeded; only observed authentication and authorization are reported
as verified access.

The SQL inventory branch records typed `sqlLogin`, `sqlImpersonate`,
`sqlImpersonateAny`, `sqlLinkedServer`, and `sqlLinkedLogin` observations in
`sql_edges`. The SQL login row preserves a tri-state `sysadmin` result, and
impersonation grants are candidates rather than verified execution rights.
Linked-server names resolve to `target_host` only when they match exactly one
live-observed host in `--allow-target`; unresolved and ambiguous names remain
in the report with `in_scope=false`. The playbook does not contact a linked
server or grant SQL roles because of an inventory edge. SQL sysadmin status
does not count as Tier Zero access without a separate verified DC admin login.

For each authenticated same-domain LDAP identity, the default read-only ACL
branch queries computed `tokenGroups` and the domain-root DACL. It records
conditional assessments for both replication rights under the listed directory
SIDs and assumed authenticated network-logon SIDs. A `candidate` requires both
rights to assess as allowed; it does not prove DCSync, a complete Windows token,
or Tier Zero access. Set `GETDA_ENABLE_ACL=0` to skip this branch. Actual NTDS
collection remains behind `GETDA_ENABLE_DOMAIN_SECRETS=1`.

The same branch locates Domain Admins, Enterprise Admins and built-in
Administrators by SID, then assesses each discovered group's DACL for member
write, full control, DACL write and owner write. The report records per-right
decisions and, when member write or full control appears allowed, a proposed
`modify-group` action with `executed=false`. It never changes group membership
by default. Set `GETDA_ENABLE_GROUP_WRITES=1` to attempt a candidate against an
observed, explicitly allowed DC. The LDAP module must resolve the group name
to the same exact DN assessed by the playbook before it writes. An acknowledged
addition triggers a fresh SMB login on that DC and an LDAP membership check
when SMB administrator access is verified. The report distinguishes the proposed,
executed, acknowledged and verified stages. These are conditional candidates
based on the reported directory SIDs and assumed logon SIDs; the ACL assessment
alone does not establish effective access or Tier Zero. DACL and owner write
candidates need additional transitions before a membership action could be
proposed.

For a specifically named same-domain user, set `GETDA_RESET_TARGET_USER=USER`
to assess that user's DACL for `ForceChangePassword` and full control. This
assessment is read-only. Set `GETDA_ENABLE_PASSWORD_RESET=1` as well to let an
eligible, authenticated identity attempt the reset through the typed
`change-password` module. The playbook generates a replacement password, and
the module stores it in NetExec's credential database after the RPC change is
acknowledged and returns the stored row ID. The playbook then queues a database
reference across the explicitly allowed hosts, using NetExec's cross-protocol
credential resolver for later logins; only a subsequent authenticated login can
establish access.
Neither an ACL candidate nor an acknowledged password change counts as Tier
Zero proof.

Set `GETDA_RESET_TARGET_USER=auto` to search for user accounts with direct or
nested `memberOf` membership in the Domain Admins group identified by SID in
this run. The playbook sorts the returned users by account name and assesses at
most 12 DACLs by default; set `GETDA_MAX_AUTO_RESET_TARGETS` to change that
limit. This LDAP filter does not find users whose membership exists only through
`primaryGroupID`. In auto mode, `GETDA_ENABLE_PASSWORD_RESET=1` permits at most
one reset attempt against a conditional `ForceChangePassword` or `GenericAll`
candidate. A reset is still only an acknowledged directory change until the
new database credential authenticates to an allowed host. Both toggles are
required to attempt a reset; the default is read-only.

```sh
GETDA_RESET_TARGET_USER=auto GETDA_ENABLE_PASSWORD_RESET=1 \
  nxc playbook DC_IP examples/playbooks/getDomAdmin.py \
  -d DOMAIN -id CREDENTIAL_ID --dns-server DC_IP --threads 1
```

```sh
GETDA_RESET_TARGET_USER=TARGET_USER GETDA_ENABLE_PASSWORD_RESET=1 \
  nxc playbook DC_IP examples/playbooks/getDomAdmin.py \
  -d DOMAIN -id CREDENTIAL_ID --dns-server DC_IP --threads 1
```

Set `GETDA_ENABLE_MACHINE_CREATE=1` to let one authenticated, same-domain LDAP
identity create a machine account when the typed MachineAccountQuota result is
positive on an observed DC. The playbook generates its name and password, uses
`add-computer`, confirms the resulting NetExec database row, and queues that
row as a credential for the allowed-host traversal. A created machine account
is an identity and a possible starting point for later delegation paths; it is
not evidence of administrator access. The toggle is off by default.

The default read-only ACL branch also assesses computer accounts whose live
identities match explicitly allowed, same-domain hosts. It checks write access
to `msDS-AllowedToActOnBehalfOfOtherIdentity`, its property set, full control,
DACL write, and owner write. Set `GETDA_RBCD_TARGET_ACCOUNT` to one exact
computer `sAMAccountName` to limit this assessment to that account. The report
records a conditional candidate even when no write is attempted. A computer's
DNS name must match exactly one host identity observed in this run before the
playbook can propose a write; saved workspace hostnames alone do not qualify.

With `GETDA_ENABLE_MACHINE_CREATE=1` and `GETDA_ENABLE_RBCD_WRITE=1`, a positive
write-property or full-control assessment can add the created machine account
as an RBCD source on that selected computer. The playbook passes the exact
assessed DN to `rbcd`, records LDAP acknowledgment and readback separately, and
keeps the created source's NetExec database credential reference. The write
toggle is off by default, and at most one grant can be confirmed per run. DACL
and owner write candidates are recorded but do not trigger an RBCD change. For a later ticket attempt, also set
`GETDA_ENABLE_DELEGATION_TICKETS=1` and `GETDA_DELEGATE_USER=USER`.

```sh
GETDA_ENABLE_MACHINE_CREATE=1 GETDA_RBCD_TARGET_ACCOUNT='WEB1$' \
GETDA_ENABLE_RBCD_WRITE=1 GETDA_ENABLE_DELEGATION_TICKETS=1 \
GETDA_DELEGATE_USER=USER nxc playbook DC_IP examples/playbooks/getDomAdmin.py \
  -d DOMAIN -id CREDENTIAL_ID --dns-server DC_IP --allow-target WEB1_IP --threads 1
```

For RBCD targets with a full `HOST/` SPN, the ticket branch also asks the KDC
for its `cifs/` alias. A saved CIFS ccache is scoped to the one observed host
and queued only for SMB. Ticket issuance, SMB authentication, administrator
access, and Tier Zero access remain separate evidence stages. The RBCD write
and resulting ticket path have not yet been verified live in GOAD.

Set `GETDA_ENABLE_GMSA=1` to read gMSA account keys through the LDAP action and
add readable NT hashes or AES256 keys to the credential frontier. This toggle
does not enable NTDS/DCSync. AES keys are queued only when `--kdcHost` names an
explicitly allowed IP. Unreadable gMSA accounts remain typed observations rather
than credentials.

The LDAP delegation branch records typed source-to-service edges from the
`delegation` module. To request a ccache when the current credential owns an
eligible constrained or RBCD path, set both
`GETDA_ENABLE_DELEGATION_TICKETS=1` and `GETDA_DELEGATE_USER=USER`. The playbook
requires the service hostname to match exactly one explicitly allowed host
identity already observed in the run. It waits until host identities have been
collected before making the ticket request against the allowed LDAP server.
The report lists `delegation_edges` and `delegation_tickets`. CIFS, LDAP and
MSSQLSvc ccaches are queued for SMB, LDAP and MSSQL respectively on their exact
allowed hosts, with the allowed KDC fixed to the DC that issued each ticket.
Ticket records and credential summaries include `expires_at` as Unix UTC
seconds when the issuing module supplies it. A known expired ccache is rejected
before entering the frontier or opening a protocol session.
A successful login through the matching protocol is recorded as an access edge.
Other service tickets remain artifacts until their matching protocol has an
authentication path. Ticket issuance alone proves neither service
authentication nor administrator access. Delegation edges from a
partially failed LDAP lookup carry `complete=false` and are never used to
request a ticket.

For an explicit delegation test in a lab:

```sh
GETDA_ENABLE_DELEGATION_TICKETS=1 GETDA_DELEGATE_USER=hodor \
  nxc playbook 10.60.0.11 examples/playbooks/getDomAdmin.py \
  -d north.sevenkingdoms.local -u svc_nxc_delegation -p LOGIN_PASSWORD \
  --dns-server 10.60.0.11 --allow-target 10.60.0.22 --threads 1
```

An existing credential in NetExec's workspace can seed the same run with
`-id CREDENTIAL_ID`. The ID is resolved against the protocol database used for
that connection; the playbook carries the resolved identity and secret when it
changes protocols.

`krbtgt` hash recovery appears under `tier_zero_material` and does not by itself
prove DC access or Domain Admin membership. `tier_zero_reached` requires an
authenticated SMB session with administrator access on an observed DC.
