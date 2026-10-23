# AD hardening posture

`examples/playbooks/chains/ad_hardening_posture.py` produces one typed verdict
describing the controls that gate NTLM relay on a host — SMB signing, LDAP
signing, LDAP channel binding (EPA), MSSQL channel binding, and which coercion
interfaces answer. It is detection-only: the signing/channel-binding facts are
read straight off NetExec's connection, and coercion exposure is probed with
`coerce_plus` and **no** listener, so no coercion is triggered and no relay is set
up. Nothing is exploited. Unlike the other chains it is target-agnostic — point it
at any DC or member host.

## Run it

Unauthenticated (SMB/LDAP signing and LDAP channel binding are observable without
a login):

```sh
nxc playbook dc.example.test examples/playbooks/chains/ad_hardening_posture.py
```

With a credential (adds MSSQL channel binding and the coercion survey, both of
which require authentication):

```sh
nxc playbook dc.example.test examples/playbooks/chains/ad_hardening_posture.py -u analyst -p 'PASSWORD' -d example.test
nxc playbook dc.example.test examples/playbooks/chains/ad_hardening_posture.py -u analyst -H NTHASH -d example.test
```

## What it reports

A per-host summary is printed and the full typed `HardeningPosture` is saved under
`NXC_PATH/playbooks/`:

- **SMB** — `signing_required` (True = relay-to-SMB is blocked). Read from the SMB
  negotiate response, so it is available even unauthenticated.
- **LDAP** — `signing_required` and `channel_binding` (`Always` is hardened;
  `When Supported` / `Never` leave LDAP/LDAPS relay open). Read from NetExec's
  native LDAP signing/CB probe (the retired `ldap-checker` module is not used).
- **MSSQL** — `channel_binding` `required` / `not required`, via the typed
  `mssql_cbt` module. Only assessed when the server negotiates TLS and a Windows
  login is available; otherwise it is reported as not assessed.
- **Coercion** — each of DFSCoerce, ShadowCoerce, PetitPotam, PrinterBug and MSEven
  marked reachable or not. This performs authenticated RPC interface binds only; it
  never sends a coercion to an attacker host.

The final `ad_hardening_posture` finding is `success` when SMB signing is required,
LDAP signing is enforced, LDAP channel binding is `Always`, and no coercion
interface answered; otherwise it is `negative` and `data.weaknesses` lists each
gap. An unreachable protocol is treated as *unknown*, never counted as a weakness.

## Caveats

- Signing/channel-binding reflect the target's current negotiation, not Group
  Policy intent; a host can require signing while policy elsewhere does not.
- A reachable coercion interface is relay *potential*, not a working relay — it
  still depends on a non-signing relay target elsewhere in the environment.
- `coerce_plus` has no typed result contract yet, so the coercion verdict is parsed
  from its log output. Giving the coercion/detection modules typed results is the
  tracked follow-up that would let this (and the master sweeps) stop string-parsing.
