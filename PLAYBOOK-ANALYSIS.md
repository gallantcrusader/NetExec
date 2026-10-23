# NetExec Playbooks — Quality Analysis, Improvements & Roadmap

*Assessment of the `gallantcrusader/NetExec` playbooks subsystem: engine, example
playbooks, documentation — and what to add next given 2024–2026 protocol attack
developments. Analysis only; no code changed.*

---

## 1. Executive summary

The playbooks feature is in good shape. The **engine** (`nxc/playbooks/`) is
genuinely well-engineered — a typed result contract, honest status semantics,
cross-host credential plumbing, and ~80 test files. The **example playbooks** are
a tier below the engine: the flagship `goad_cross_host_sql.py` and the two
`master_playbook_*` sweeps are excellent, but there's noticeable drift — two
chains still use pre-P0 accessors, ~200 lines are duplicated verbatim across the
masters, and the master sweeps fall back to **parsing English log strings**
because the high-value modules they call don't expose typed results.

The single biggest opportunity is strategic, not stylistic: NetExec already ships
141 modules including the current meta (`badsuccessor`, `shadow-creds`, `rbcd`,
`delegation`, `timeroast`, `coerce_plus`, `mssql_coerce`, `certipy-find`,
`entra-id`), but **the playbooks orchestrate almost none of them**. The example
set covers SMB/LDAP/MSSQL enumeration well and barely touches Kerberos, ADCS
beyond detection, delegation, coercion, SSH/RDP/WINRM lateral movement, or
secrets post-ex. Closing that gap — plus giving the modern modules typed result
contracts so playbooks can branch on them — is where the next units of work pay
off most.

Grades:

| Area | Grade | One-line |
|---|---|---|
| Engine (`runner/results/contracts/capture/access`) | **A** | Clean, honest, well-tested; a reference implementation |
| Flagship chain + master sweeps | **A−/B+** | Sophisticated; let down by duplication & string-scraping |
| Non-flagship chains (laps/acl/khal_ca) | **B−** | Work, but on the old API; hand-tracked evidence |
| Teaching examples | **B** | Good for SMB/LDAP/MSSQL; nothing for Kerberos/SSH/RDP/WINRM |
| Protocol/technique coverage vs. 2025–26 meta | **C+** | Modules exist; playbooks don't wire the modern ones |
| Documentation | **A−** | 69 KB reference + per-chain cookbooks + honest coverage doc |

---

## 2. What's strong

**The result model is the backbone and it's right.**
`ActionResult` carries `status / data / inputs / events / artifacts / error / index`,
and `contracts.py` enforces that every typed result is a dataclass that round-trips
through `json_value()` — binary becomes base64, enums/paths/datetimes/Decimals are
handled, anything unserializable raises at record time rather than corrupting the
JSON file. `kind="typed"` vs `kind="captured"` cleanly separates "module gave me
structured data" from "I scraped its log output," and `ModuleResult` transparently
proxies single-result access while staying iterable for multi-host hooks. This is
the kind of API that makes downstream playbooks short and safe.

**Status semantics are epistemically honest.** The `SUCCESS / NEGATIVE / FAILED /
SKIPPED` split is used consistently to mean "it worked / it ran and the answer is
no / it errored / privileges absent." `NEGATIVE` being branchable (not an error)
is exactly what you want for "no anonymous access" as a *finding*. This honesty
runs through the whole project: `access.py`'s DACL assessor refuses to overstate —
it bails to an explicit "unresolved" reason on OWNER RIGHTS, object-type GUID
scoping, and standard-rights-with-object-GUID cases rather than pretending it
constructed a Windows token, and the coverage doc repeatedly says "configuration
evidence, not executed compromise." For a tool whose output lands in client
reports, that discipline is worth a lot.

**Cross-host credential plumbing is careful.** `CredentialRef(protocol, id)` lets a
secret proven on one protocol be replayed on another, and `apply_credential()` /
`find_stored_credential()` handle the real-world messiness — plaintext/hash/aesKey/
ssh-key types, domain matching, the `LM:NT` vs `NT` hash forms, and the fact that a
CLI `-id` belongs to one protocol's DB so it's cleared when reusing a secret
cross-protocol. Session reuse keyed on `(protocol, anonymous, credential, options)`
with explicit `fresh=` and teardown is the right design.

**The master sweeps are genuinely good tradecraft.** Thread-local narration so
concurrent targets don't interleave, a hard wall-clock cap so a filtered SSH/RDP/
VNC port can't freeze the sweep, spider-and-download so "readable" means "grabbed,"
and a tri-state vuln verdict that strips negative phrases before matching. The
anon sweep probing `null` / `Guest` / `thisuserdoesnotexist` to reveal
guest-mapping is a nice touch.

**Tests and docs are not an afterthought.** ~80 `test_playbook_*.py` files,
contract-validation tests, a 69 KB `docs/playbooks.md`, per-chain cookbooks, and a
`goad-path-coverage.md` that honestly tracks what's verified vs. outstanding
(including a "Framework gaps" list). Most tools this size don't document their own
limitations.

---

## 3. Areas for improvement

Ordered by payoff.

### 3.1 Give the modern/detection modules typed result contracts *(highest leverage)*
`delegation`, `rbcd`, `enum_links`, `laps` declare a dataclass `result_type` and
are a joy to consume from a playbook (`.rows`, `.one()`, `data.delegations`). But
the modules that matter most for 2025–26 — `badsuccessor`, `shadow-creds`,
`timeroast`, `coerce_plus`, `certipy-find`, and the detection modules `zerologon`,
`nopac`, `printnightmare`, `adcs`, `sccm` — **don't**, so a playbook calling them
gets `kind="captured"` and must scrape log text. This is the root cause of 3.2.
Prioritize typed `result_type`s (even minimal: `vulnerable: bool`, `detail: str`,
plus the structured hits) for the detection + modern-technique modules. It's the
one change that makes everything downstream cleaner.

### 3.2 Kill the log-string heuristics in the master sweeps
`_vuln_status`, `_enum`, `_BLOCKED`, `_NEG`, `_CANT` decide "VULNERABLE / denied /
safe" by substring-matching English log messages ("vulnerable", "not vulnerable",
"access denied", "0xc0000022"). This is fragile against any wording change,
localization, or a module that phrases a hit differently, and a false "safe" in a
security tool is the dangerous direction. It exists only because of 3.1. Once the
detection modules return typed verdicts, replace the heuristics with
`result.data.vulnerable` / status checks and keep the string matching strictly as a
last-resort fallback for genuinely legacy `captured` modules.

### 3.3 De-duplicate the two master playbooks
~200 lines (lines ~45–450 of each) are **identical** — the files even label the
block "shared engine (identical in both master playbooks)." Extract it to
`examples/playbooks/_sweep_engine.py` (or `teaching/patterns/`) and have both
masters import it; keep only the per-file config (`IDENTITIES`, `AUTH_MODE`,
`VULN_IDENT`, titles) in each. Right now a fix to `_enum` has to be made twice,
which is how the two copies eventually drift.

### 3.4 Finish migrating the chains to the P0 API
`goad_cross_host_sql.py` uses the modern ergonomics (`host.evidence()`,
`.one()`, `.rows`, `host.finding()`); `goad_laps_path.py` and `goad_acl_chain.py`
still hand-track `len(host.run.results) - 1` and build `ActionResult(...)` by hand
with `host.record(...)`. Since these are the *teaching* reference for how to write
a chain, the inconsistency teaches the old way. Port them to
`with host.evidence() as ev` + `host.finding(...)`. (Per project notes this is the
staged-but-uncommitted P1 work; it's worth completing.)

### 3.5 Isolate the one active step in the "read-only" sweep
`master_playbook_authenticated.py` is documented as read-only "with ONE active
exception": `pre2k(all=True)` attempts Kerberos pre-auth for pre-created computer
accounts. It's honestly flagged, but an active auth attempt buried inside a sweep
most operators will treat as passive is a footgun on a careful engagement. Gate it
behind an env flag (`NXC_PRE2K_ACTIVE=1`) or move it to a dedicated
`chains/pre2k_precreated.py`, so "the master sweep" stays truly passive by default.

### 3.6 Minor engine/robustness notes
- **Leaked sessions on timeout.** `_run_bounded` abandons the daemon thread when a
  probe exceeds `SIMPLE_PROBE_TIMEOUT`; the underlying socket/session isn't closed,
  so across a large target list these accumulate. Acceptable tradeoff for a sweep,
  but worth a comment and perhaps a best-effort close.
- **`__getattr__` dynamic dispatch** on `HostContext`/`ProtocolSession` is elegant
  but means typos in protocol/action names surface as `AttributeError`/`ValueError`
  at call time with no IDE/autocomplete help. A generated stub or an explicit
  registry would help playbook authors; low priority.
- **`.DS_Store`** is sitting in `examples/playbooks/teaching/`. Add to
  `.gitignore` and don't commit it.
- **`pre2k`/spider output paths** are documented as living under `NXC_PATH` but the
  checklist only says "see NXC_PATH/modules/pre2k/<domain>/"; surfacing the exact
  artifact paths as `Artifact` objects on the result would make them machine-usable.

### 3.7 Credential lifecycle: tickets & certificates
`CredentialRef` represents password/hash/aesKey/ssh-key rows. It can't yet carry a
**TGT/ccache or a certificate** as a first-class reusable reference (the author's
own "Framework gaps" calls this out). This is the structural blocker for clean
Kerberos and ADCS chaining — see §5. Until a ticket/cert can be stored and replayed
like a credential row, delegation/shadow-cred/ESC chains have to pass `KRB5CCNAME`
and file paths around out-of-band.

---

## 4. Current coverage vs. the module library

NetExec ships **141 modules** and **10 protocols** (smb, ldap, mssql, ssh, rdp,
winrm, wmi, ftp, nfs, vnc). The example playbooks exercise only:

- **Protocols in examples:** smb (21×), ldap (18×), mssql (8×). **Zero** ssh / rdp /
  winrm / wmi beyond the master sweeps' reachability probe.
- **Modules in examples:** `adcs`, `check-impersonation`, `daclread`, `enum_ca`,
  `enum_impersonate`, `enum_links`, `exec_on_link`, `get-desc-users`, `laps`, `maq`,
  `mssql_priv`, `pre2k`, `sccm`, `spider_plus`, `token-groups`, `user-desc`.

So ~16 of 141 modules appear in a playbook, and the **current attack meta is almost
entirely absent** from the playbooks even though the modules exist:
`badsuccessor`, `shadow-creds`, `rbcd`, `delegation`, `timeroast`, `coerce_plus`,
`dfscoerce`, `shadowcoerce`, `petitpotam`, `printerbug`, `efsr_spray`,
`mssql_coerce`, `mssql_cbt`, `ntlm_reflection`, `remove-mic`, `certipy-find`,
`masky`, `dpapi_hash`, `lsassy`, `nanodump`, `handlekatz`, `entra-id`, `msol`,
`raisechild` (child→parent), `enum_trusts`, `ntds-dump-raw`, `ntdsutil`.

**The gap is orchestration, not capability.** That's the good news: most of §5 is
"write a playbook that wires modules that already exist," not "implement an attack."

---

## 5. What to add — modules & playbooks, mapped to 2024–2026 developments

Each item notes the real technique, why it matters now, and what's needed (new
playbook, typed result, or new module). Grouped by protocol.

### LDAP / Active Directory
- **BadSuccessor (dMSA abuse)** — 2025 (Akamai). A `msDS-DelegatedManagedServiceAccount`
  can be made to "supersede" a target account and inherit its privileges without
  touching the target's ACL; abusable with only *create* rights on an OU. Module
  `badsuccessor` exists → **add a typed result + a `chains/badsuccessor.py`**
  (enumerate abusable OUs → stage dMSA → show the inherited-privilege evidence,
  detection-only by default). This is arguably the highest-value single addition.
- **Shadow Credentials (`msDS-KeyCredentialLink`)** — write a KeyCredential to a
  target, then PKINIT as it and **UnPAC-the-hash** to recover the NT hash. Module
  `shadow-creds` exists → **typed result + `chains/shadow_credentials.py`** pairing
  write → PKINIT → NT hash → reuse as a `CredentialRef`. Blocked partly by §3.7
  (cert/ticket as a credential).
- **LDAP channel binding + signing enforcement** — Server 2025 *fresh installs*
  default to requiring LDAP signing and set channel binding (EPA) to "when
  supported" with auditing; in-place upgrades keep prior (looser) settings. This
  erodes the classic unsigned/un-bound LDAP relay surface and pushes relay toward
  ADCS/Kerberos and non-compliant legacy hosts. The engine **already captures**
  `signing_required` and `channel_binding`/`cbt_status` at connect time. **Add a
  `chains/ad_hardening_posture.py`** that reports per-DC LDAP signing/CB and SMB
  signing posture — a fast, defensible, client-ready "are you hardened?" deliverable
  with near-zero new code. (`ldap-checker`, `mssql_cbt` modules support this.)
- **ADCS ESC1–ESC16** — detection via `adcs`/`enum_ca`/`certipy-find` exists, but no
  playbook goes past *finding* a template. **Add `chains/adcs_esc.py`** that
  classifies ESC1/ESC2/ESC3/ESC4/ESC6/ESC8 and the newer **ESC9** (no security
  extension), **ESC10** (weak cert mapping), **ESC11** (relay to CA ICPR RPC),
  **ESC13** (issuance-policy→group), **ESC14** (weak `altSecurityIdentities`
  mapping), **ESC15 "EKUwu" / CVE-2024-49019** (EKU/app-policy injection into v1
  templates), **ESC16** (CA-wide security extension disabled), requests where safe,
  and emits the template/CA evidence. Needs typed `certipy-find` output. *(ESC14–16
  labels are community-maintained, not Microsoft-canonical; ESC16's exact
  definition varies by source — worth pinning to SpecterOps/Certify when
  implementing.)*
- **Pre-created computer accounts (pre2k)** and **machine account quota (maq)** —
  both wired in the sweeps already; promote to a small `chains/precreated_and_maq.py`
  that ties MAQ>0 + pre2k hits into an "attacker can add a computer / owns a stale
  one" verdict.
- **Trusts / child→parent (`raisechild`, `enum_trusts`, SID history)** — no playbook.
  Add a trust-enumeration + SID-filtering-posture report.

### Kerberos
- **Roasting pipeline** — the sweeps *enumerate* kerberoastable/AS-REP-roastable
  accounts but stop there. Add `chains/roast_and_reuse.py`: roast → write hashes as
  artifacts → (optional offline crack hook) → replay a recovered credential as a
  `CredentialRef` across protocols. Ties roasting to the credential graph.
- **RBCD end-to-end** — `rbcd` (read/write, typed) and `delegation` (S4U, typed)
  both exist but **no chain wires them**. Add `chains/rbcd_takeover.py`: confirm
  write to `msDS-AllowedToActOnBehalfOfOtherIdentity` → request S4U2Self/S4U2Proxy
  via `delegation` → verify service access. This is the cleanest "modules already
  typed, just orchestrate" win.
- **Constrained/unconstrained delegation abuse** — `delegation` module can request
  tickets; add a chain that goes enum → prerequisite check → S4U → verify, instead
  of the sweep's enum-only `find_delegation`.
- **Timeroasting** — 2025 technique (no pre-auth needed; roast computer-account
  RID-based hashes via Netlogon time sync). Module `timeroast` exists → typed result
  + a teaching example; high-signal because it needs no credentials.
- **Diamond/Sapphire tickets, S4U2self/U2U, UnPAC-the-hash** — document the
  boundary (NetExec is for recon/auth/exec, ticket forging is impacket/Rubeus
  territory) and provide the credential/ticket handoff (§3.7) so playbooks can
  *consume* tickets those tools mint.

### SMB
- **NTLM reflection — CVE-2025-33073 (SMB client EoP → SYSTEM)** — June 2025. Coerced
  auth is reflected back to the originating host (crafted marshalled/DNS target
  name) to run as SYSTEM on any machine not enforcing SMB signing; Synacktiv's
  write-up is the authoritative root cause (some outlets mislabel it "reflective
  Kerberos relay"). The fork already ships `ntlm_reflection` and `remove-mic` →
  **add a typed result + a detection teaching example** that reports exposure
  (reachable + signing-not-enforced). Current, specific, and module-backed.
- **Coercion matrix** — `petitpotam`, `dfscoerce`, `shadowcoerce`, `coerce_plus`,
  `printerbug`, `efsr_spray` all exist. Add `chains/coercion_survey.py` that
  *detects* which coercion vectors a host answers (detection-only; no relay fired)
  and reports it alongside SMB signing — directly tied to the relay risk story.
  **Scope note:** NetExec coerces but does not relay (no `ntlmrelayx`); the playbook
  should say so and hand off.
- **Null session / RID cycling** — already covered (`rid_brute`); fine.
- **SMB signing posture** — folded into the hardening-posture playbook above.
- **SMB over QUIC (port 443, Windows Server 2022+)** — emerging; note as a probe to
  add to reachability if/when the protocol layer supports it.

### MSSQL
- **Linked-server chains** — `goad_cross_host_sql.py` is the flagship and it's good.
  Generalize it beyond GOAD's hardcoded hosts into a `chains/mssql_link_crawl.py`
  that discovers the link graph (`enum_links`) and walks it to depth-N with
  `exec_on_link`, reporting the reachable-sysadmin frontier.
- **Coerced auth via MSSQL (`xp_dirtree`/`xp_fileexist`)** — `mssql_coerce` exists;
  add to the coercion survey (MSSQL service account → coercible to attacker host).
- **Impersonation (`EXECUTE AS`)** — `enum_impersonate`/`check-impersonation` wired;
  combine with link crawl for "impersonate → cross-link" paths.
- **xp_cmdshell / CLR / ADSI credential theft** — `enable_cmdshell`,
  `link_enable_cmdshell`, `link_xpcmd` exist; add an *explicitly active* exec
  teaching example (clearly labeled, opt-in) so the exec path is documented, not
  just enumeration.

### SSH
- **regreSSHion (CVE-2024-6387)** and **Terrapin (CVE-2023-48795)** — add a typed
  SSH posture check: banner/version (regreSSHion hit sshd 8.5p1–9.7p1 on glibc
  Linux, fixed 9.8p1) plus KEX/cipher inspection for Terrapin prefix-truncation
  exposure (`chacha20-poly1305@openssh.com` and CBC-EtM modes). Currently SSH is
  only a reachability + `sudo_check` probe.
- **Key-based lateral movement** — the credential layer already stores ssh `key`
  creds and `apply_credential` replays them. Add `chains/ssh_key_reuse.py`:
  harvest keys (shares/home dirs) → store → attempt reuse across the host list.
  Shows off cross-host `host.at()` + `CredentialRef` on a non-Windows protocol.

### RDP
- **PtH over RDP / Restricted Admin mode** — detection teaching example: is
  Restricted Admin enabled (NLA + `DisableRestrictedAdmin`)? That's the PtH-over-RDP
  precondition. `rdp`, `shadowrdp`, `rdcman` modules exist.
- **RDP cached creds / `rdcman`/`mremoteng` stored connections** — harvest-and-report
  teaching example (both modules exist); common real-world lateral path.
- **BlueKeep (CVE-2019-0708)** — legacy, but a detection-only probe is cheap for
  old estates.

### WINRM / WMI / DCOM
- **No WINRM/WMI playbooks exist at all** beyond reachability. Add teaching examples:
  `teaching/winrm/exec.py` (PtH/overpass command exec, clearly active/opt-in) and
  `teaching/wmi/exec.py` (DCOM lateral movement). These are the bread-and-butter
  lateral-exec methods and the playbook set has a conspicuous hole here.
- **PowerShell logging / AMSI relevance** — document detection of
  ScriptBlock/Module logging + AMSI as a posture check so operators know their exec
  noise level.

### Secrets / post-exploitation (cross-protocol)
- **DPAPI / LSASS / SAM-LSA** — once local admin is reached (the LAPS chain already
  gets there), nothing harvests secrets. Add `chains/secrets_harvest.py` wiring
  `--sam`/`--lsa`, `dpapi_hash`, `lsassy`, `nanodump`, `handlekatz` — strictly
  gated behind confirmed admin + an opt-in flag, feeding recovered creds back as
  `CredentialRef`s. Closes the loop from "I have admin" to "here's what I can reuse."

### Entra / hybrid identity
- **AD → Entra pivot** — `entra-id`, `msol` modules exist; no playbook. Add a
  hybrid-identity recon playbook (Entra Connect / sync server discovery via
  `entra-id` module + `msol`) reflecting the 2024–26 shift of AD attacks into cloud
  identity (Entra Connect sync-account abuse, Seamless SSO Silver tickets, Golden
  SAML, PRT theft). Also worth noting for the graph story: **BloodHound CE** and
  **OpenGraph** (BloodHound v8.0, July 2025) now ingest non-AD/Entra data — the
  playbooks' BloodHound collection could target CE directly.

---

## 6. Suggested prioritization

**Tier 1 — do first (small, high value, mostly orchestration):**
1. Typed `result_type`s for the detection + modern modules (§3.1) — unblocks everything.
2. De-dup the master sweeps into a shared engine module (§3.3).
3. `chains/ad_hardening_posture.py` — signing/channel-binding/coercion report (§5 LDAP/SMB); near-zero new code, immediately client-useful.
4. `chains/rbcd_takeover.py` — both modules already typed (§5 Kerberos).

**Tier 2 — the current meta:**
5. `badsuccessor` typed result + chain (§5 LDAP).
6. `shadow_credentials` chain (needs §3.7 cert/ticket credential work).
7. `adcs_esc.py` covering ESC1–ESC16 past detection.
8. Coercion survey + NTLM-reflection (CVE-2025-33073) + MSSQL coerce (§5 SMB/MSSQL).
9. Finish porting laps/acl chains to the P0 API (§3.4).

**Tier 3 — fill the protocol holes & post-ex:**
10. WINRM/WMI exec teaching examples (§5 WINRM/WMI).
11. SSH posture (Terrapin/regreSSHion) + key-reuse chain (§5 SSH).
12. RDP Restricted-Admin / stored-cred harvest (§5 RDP).
13. `secrets_harvest.py` DPAPI/LSASS loop-closer (§5 secrets).
14. Entra/hybrid recon (§5 Entra); trusts/child→parent (§5 LDAP).

**Cross-cutting:** §3.7 (ticket/certificate credential references) is a structural
prerequisite that makes items 6, 7, and the Kerberos chains clean rather than
file-path-juggling — worth scheduling early even though it's engine work.

---

## 7. Bottom line

The engine is production-quality and the honesty of its result model is a real
differentiator for a reporting-adjacent tool. The example playbooks are strong
where they exist but lag the engine and, more importantly, lag NetExec's own module
library — the 2025–26 attack techniques are already implemented as modules and
simply aren't wired into playbooks yet. The highest-leverage work is therefore
cheap: give the modern/detection modules typed results, then write a handful of
chains that orchestrate what's already there (hardening posture, RBCD, BadSuccessor,
ADCS ESC, coercion survey). That converts "NetExec has a module for it" into
"NetExec has a one-command, evidence-producing playbook for it," which is the whole
point of the feature.
