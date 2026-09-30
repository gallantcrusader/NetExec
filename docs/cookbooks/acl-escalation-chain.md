# ACL abuse escalation chain

## Goal

Read the Sevenkingdoms domain and verify that every ACE of a known object-takeover path is present, without touching any of them. The playbook walks the eight-edge chain `tywin.lannister → jaime.lannister → joffrey.baratheon → tyron.lannister → Small Council → DragonStone → KingsGuard → stannis.baratheon → kingslanding$` (the DC computer object), checking each hop's exact right — ResetPassword, GenericWrite, WriteDacl, SelfMembership, WriteMembers, WriteOwner, GenericAll — against the target's DACL, and for the *user* edges it additionally assesses the DACL under explicit token assumptions. It is pure directory recon: it collects candidate-path evidence and never executes a single transition (`transitions_executed` stays `False`).

## Target and roles

- **Starting target (must be exactly this):** `10.60.0.10` — Kingslanding, the `sevenkingdoms.local` DC. The playbook raises `ValueError` if `host.target` is anything else.
- **`--allow-target` hosts:** none. The playbook only opens `host.ldap()` on the single target; it makes no `host.at()` pivot, so no allow-list entries are required.
- **Run as:** any authenticated `sevenkingdoms.local` domain user — reading `nTSecurityDescriptor` and `tokenGroups` over LDAP is available to Authenticated Users. In this lab use `tywin.lannister` / `powerkingftw135` in domain `sevenkingdoms.local`. The tool never logs in *as* the chain principals; it only needs directory read, not any of the chain's write rights.

## Command

```
nxc playbook 10.60.0.10 examples/playbooks/chains/goad_acl_chain.py \
    -u tywin.lannister -p powerkingftw135 -d sevenkingdoms.local
```

## Walkthrough (each step maps to the code)

1. **Guard the target.** `if host.target != "10.60.0.10": raise ValueError(...)` — this playbook is pinned to Kingslanding.
2. **Open the LDAP session.** `ldap = host.ldap()` opens an LDAP `ProtocolSession` using the CLI `-u/-p/-d`. `if not ldap.ok: return` bails out (recording nothing) when the session is not connected and usable.
3. **Define the candidate chain.** Eight tuples `(principal, target, right, masks, object_guid)` describe the path. The `masks` are the access-mask bits the ACE must carry (e.g. `0x100` ExtendedRight for ResetPassword, `0x40000` WRITE_DAC for WriteDacl, `0x80000` WRITE_OWNER for WriteOwner, `0xF01FF`/`0x10000000` for GenericAll); `object_guid` is the schema GUID the ACE must be scoped to (the ForceChangePassword extended right for ResetPassword, the `member` attribute GUID for SelfMembership/WriteMembers, or `None`).
4. **Read each target's DACL.** Per edge, `result = ldap.module("daclread", target=target, principal=principal, ace_type="all")` returns a `ModuleResult`; `result.data.objects` are the matched objects and `result.data.principal_sid` is the resolved principal SID.
5. **Match ACEs precisely.** For each object's flagged `matches`, an ACE at `obj["descriptor"]["aces"][index]` is kept only when it is `access == "allowed"`, not `inherit_only`, its `object_type` equals the expected GUID, and its mask contains a full expected mask (`ace["mask"] & mask == mask`). Hits are stored in `edge["matching_aces"]` as `{dn, ace_index}`.
6. **Skip group edges (by design).** For `Small Council`, `DragonStone`, and `KingsGuard` the principal is a group you would only be *inside* after an earlier membership transition, so the code sets `edge["assessment_limit"] = "Group edge requires the token after the preceding membership transition"` and moves on — no token pull, no assessment.
7. **Pull computed groups for user edges.** `groups = ldap.module("token-groups", principal=principal)`; if `not groups.ok or not groups.data.groups_returned` it records `assessment_limit = "Computed directory groups unavailable"` and skips the assessment.
8. **Assess the DACL under stated assumptions.** It records `assumed_logon_sids = ["S-1-1-0", "S-1-5-11", "S-1-5-2"]` (Everyone / Authenticated Users / Network) plus the `directory_sids` from `tokenGroups`, then calls `assess_dacl(descriptor, directory_sids + assumed_logon_sids, masks[0], object_type=guid, target_sid=obj["sid"])` per object. `assess_dacl` walks ACEs in canonical order (honoring deny-before-allow, resolving `SELF` to the target SID, mapping generic→specific masks) and returns a `DACLAssessment(decision, requested_mask, remaining_mask, reason, ace_indices)`. It explicitly does **not** build a real Windows token.
9. **Compute and record the verdict.** `data.candidate_chain_present = all(edge["matching_aces"] for edge in data.edges)`; `data.transitions_executed` is left `False`; then one `host.record(ActionResult(...))` is emitted (see below). All eight edges are always evaluated — there is no early exit.

## Expected structured verdict

The single finding is emitted by:

```
host.record(ActionResult("ldap", "goad_acl_chain", host.target,
            ResultStatus.SUCCESS if data.candidate_chain_present else ResultStatus.NEGATIVE, data))
```

- **SUCCESS** when every one of the eight edges has at least one matching ACE (`candidate_chain_present is True`). `data` (a `ChainEvidence` dataclass) records: `edges` — an ordered list, one dict per hop with `principal`, `principal_sid`, `target`, `right`, `matching_aces` (`[{dn, ace_index}]`), and either `assessments` (`[{dn, dacl: DACLAssessment}]` with `assumed_logon_sids` + `directory_sids`) for user edges or an `assessment_limit` string for skipped/group edges — plus `candidate_chain_present=True` and `transitions_executed=False`.
- **NEGATIVE** when any edge has zero matching ACEs (`candidate_chain_present is False`, a branchable "reachable directory but the path is broken" outcome). The same `ChainEvidence` shape is recorded so you can see exactly which hop's ACE is missing.
- If the LDAP session is not usable, the playbook `return`s at step 2 and records **no** finding at all.

## Safety note

Nothing is escalated. The playbook only *reads* — `daclread`, `token-groups`, and an in-memory `assess_dacl` — and `transitions_executed` is always `False`: it never resets a password, writes a DACL, adds a group member, or changes an owner. A SUCCESS verdict means only that the ACEs composing a candidate path to full control of the DC computer object `kingslanding$` are present as read from the directory — it is not proof of, and not execution of, domain compromise. The three group edges are additionally left unresolved (`assessment_limit`) because they depend on group membership that would only be acquired mid-chain.
