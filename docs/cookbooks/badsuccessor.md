# BadSuccessor exposure

`examples/playbooks/chains/badsuccessor.py` reports who can run the BadSuccessor
attack in a domain — and whether the credential you ran it with is one of them. It
is detection-only: it never creates a dMSA or changes the directory.

## Background

BadSuccessor (Akamai, 2025) abuses a **delegated Managed Service Account** (dMSA, a
Windows Server 2025 account type). A principal that can create or control a
`msDS-DelegatedManagedServiceAccount` object in an OU can make that dMSA
"supersede" a target account, so the dMSA's PAC inherits the target's SIDs and
privileges — with only create/write rights on the *OU*, and no rights on the
target. It requires a Server 2025 domain controller.

## Run it

```sh
nxc playbook dc.example.test examples/playbooks/chains/badsuccessor.py -u analyst -p 'PASSWORD' -d example.test
```

## What it does

1. Runs the typed `badsuccessor` module, which enumerates OUs and finds the
   **non-privileged** SIDs (Domain/Enterprise Admins, Builtin Administrators and
   SYSTEM are excluded) that hold an abusable right — `GenericAll`, `GenericWrite`,
   `WriteOwner`, `WriteDACL`, `CreateChild`, `WriteProperty`, or `AllExtendedRights`
   — over an OU (or own it), plus whether a Server 2025 DC is present.
2. Resolves, via `token-groups`, the SIDs the **current** credential holds, and
   intersects them with the abusable principals to decide whether *you* are
   positioned to run the attack (not merely that someone in the domain is).

The `badsuccessor` finding is `success` only when a Server 2025 DC is present **and**
the current principal holds an abusable OU right; otherwise it is `negative`, and
`data` still lists every abusable principal and OU found, the Server 2025 DCs, and
the current principal's SIDs. A per-host summary is printed and the full typed
result is saved under `NXC_PATH/playbooks/`.

## Module output (typed)

`badsuccessor` now returns a typed `ResultData`:

- `server_2025_present` / `server_2025_dcs` — whether (and which) DCs run Server 2025.
- `organizational_units` — OU entries scanned.
- `principals` — list of `{sid, name, ous}`, each a non-privileged principal with
  abusable control over those OUs.
- `vulnerable` — `server_2025_present and principals` (a reachable precondition).

## Caveats

- An abusable OU right is the BadSuccessor **precondition**, not proof of a working
  takeover — staging the dMSA and completing the supersession is a separate, active
  step left to dedicated tooling.
- Without a Server 2025 DC the abuse is not possible; the chain still reports the
  OU permissions so the exposure is visible before 2025 DCs arrive.
- The abusable-rights set is deliberately broad (it mirrors Akamai's
  `Get-BadSuccessorOUPermissions`); confirm the specific ACE grants the right to
  create a dMSA in the listed OU before acting.
