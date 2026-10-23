# Coercion survey

`examples/playbooks/chains/coercion_survey.py` produces one typed verdict
describing every way a host can be made to authenticate out — the first half of a
coercion -> NTLM-relay chain. It is a focused coercion matrix: deeper than the
coercion bundle in [`ad_hardening_posture`](ad-hardening-posture.md), it surveys
all five SMB coercion vectors plus the MSSQL coercion vector, and reports SMB
signing as the relay-risk *context*. Target-agnostic — point it at any DC or
member host.

## Coercion -> relay in one paragraph

A coercion makes a victim machine account authenticate to an attacker-chosen host
(PetitPotam, PrinterBug, etc.). On its own that is just an outbound login; it
becomes an attack when the attacker **relays** that authentication to a service
that does not require signing/channel binding (relay-to-SMB, relay-to-LDAP, …).
So a reachable coercion vector is relay *potential* — it only pays off if a
non-signing relay target exists. This chain confirms the vectors and reports SMB
signing so you can see whether relay-to-SMB on this host would be viable.

## The live module, and the retired ones

`coerce_plus` is the **only** live SMB coercion module. The old `petitpotam`,
`dfscoerce`, `shadowcoerce`, `printerbug` and `efsr_spray` modules were retired
(they now return a stub pointing at `coerce_plus`) and are not called. Run with
**no** listener, `coerce_plus` is detection-only: it binds each coercion RPC
interface and logs `VULNERABLE, <Method>` for the ones that answer — DFSCoerce,
ShadowCoerce, PetitPotam, PrinterBug, MSEven. It never fires a coercion and sets up
no relay. `coerce_plus` has no typed result contract, so the chain parses those
highlight lines from the module's events rather than its result status (per-method
errors mark the captured result FAILED even when some interfaces answered).

## The gated active MSSQL step

`mssql_coerce` is different: it has **no detection mode**. It executes
`xp_dirtree`/`xp_fileexist`-style calls to make the SQL service account
authenticate out to a listener, so the only way to "test" it is to fire it at an
attacker listener. The chain therefore runs it **only** when `NXC_COERCE_LISTENER`
is set, and marks the result as ACTIVE. Without the listener the MSSQL vector is
reported as not tested.

## Run it

Detection-only SMB coercion matrix (plus the signing context):

```sh
nxc playbook dc.example.test examples/playbooks/chains/coercion_survey.py -u analyst -p 'PASSWORD' -d example.test
```

Also actively test the MSSQL coercion vector against your listener:

```sh
NXC_COERCE_LISTENER=10.10.10.5 \
    nxc playbook dc.example.test examples/playbooks/chains/coercion_survey.py -u analyst -p 'PASSWORD' -d example.test
```

## Environment

| Variable             | Default | Effect                                                                                             |
| -------------------- | ------- | -------------------------------------------------------------------------------------------------- |
| `NXC_COERCE_LISTENER`| unset   | Attacker IP. **Only** when set does the chain ACTIVELY fire `mssql_coerce` at it (the SQL service authenticates out). Unset, the MSSQL vector is reported as not tested. |

## What it reports

A per-host summary is printed and the full typed `CoercionSurvey` is saved under
`NXC_PATH/playbooks/`:

- **SMB context** — `smb_reachable`, `smb_authenticated`, and
  `smb_signing_required` (read from the SMB negotiate response; `False` means
  relay-to-SMB is not blocked).
- **SMB coercion** — `smb_vectors`, each of DFSCoerce / ShadowCoerce / PetitPotam /
  PrinterBug / MSEven marked reachable or not. Only assessed with an authenticated
  SMB session (`smb_coercion_assessed`); detection binds only, no coercion fired.
- **MSSQL coercion** — `mssql_coerce_attempted` and `mssql_coerce_ok`. Attempted
  only with `NXC_COERCE_LISTENER` set and MSSQL reachable/authenticated; `mssql_note`
  explains why it was skipped otherwise. This step is ACTIVE.
- **Relay risk** — `relay_to_smb_viable` is set when SMB signing is off *and* a
  coercion vector is reachable.

The final `coercion_survey` finding is `success` when `exposed` is true — any SMB
coercion vector answered, or the active MSSQL coercion ran ok. Otherwise it is
`negative`, with `reason` noting what was not assessed.

## Caveats

- SMB coercion detection performs authenticated RPC interface binds and fires no
  coercion; the MSSQL step is ACTIVE and only runs behind `NXC_COERCE_LISTENER`.
- A reachable coercion vector is relay *potential*, not a working relay — it still
  depends on a non-signing relay target elsewhere in the environment.
- `coerce_plus` has no typed result contract yet, so the SMB coercion verdict is
  parsed from its log output. Giving the coercion modules typed results is the
  tracked follow-up that would let this (and the master sweeps) stop string-parsing.
