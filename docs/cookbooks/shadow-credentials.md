# Shadow Credentials

`examples/playbooks/chains/shadow_credentials.py` lists the KeyCredentials already
present on a target and — when you opt in — stages a new one and hands the resulting
PFX off to an external PKINIT + UnPAC-the-hash step. It wires the typed `shadow-creds`
module (`nxc/modules/shadow-creds.py`) into one verdict.

It is **detection-first**: with no `NXC_SHADOW_WRITE` it only *lists* (read-only). The
active LDAP write is opt-in and, by default, cleaned up afterwards.

## Background

Shadow Credentials abuses `msDS-KeyCredentialLink`, the multi-valued attribute that
holds the raw public keys an account can authenticate with (Key Trust / Windows
Hello for Business). If you can write that attribute on a target account, you can add
a key pair you control, then authenticate as the target with **PKINIT** using the
matching certificate and recover the target's NT hash via **UnPAC-the-hash** — all
without changing the target's password. A common prerequisite is `GenericWrite` /
`GenericAll` over the target (for example a computer account you created via the
machine account quota).

The PKINIT + UnPAC step is external: this chain stages the KeyCredential and the PFX,
then reports the PFX path so you continue with `certipy`/`nxc`. Like `rbcd_takeover`
reporting its ccache path, the PFX path is always reported for handoff.

## Configuration

Point the playbook at the **DC**. All inputs come from the environment so the chain
never fires by accident:

| Variable | Meaning |
| --- | --- |
| `NXC_SHADOW_TARGET` | target sAMAccountName, e.g. `WS01$` (required) |
| `NXC_SHADOW_WRITE` | set to `1` to actually add a KeyCredential — an active LDAP write (default off = list only) |
| `NXC_SHADOW_CLEANUP` | `1` (default) removes the added KeyCredential afterwards; `0` keeps it |

```sh
export NXC_SHADOW_TARGET='WS01$' NXC_SHADOW_WRITE=1
nxc playbook dc.example.test examples/playbooks/chains/shadow_credentials.py \
    -u operator -p 'PASSWORD' -d example.test
```

## What it does

1. **`shadow-creds` (list)** — records the existing KeyCredentials on the target
   (count and device IDs) from the typed `data`. Read-only.
2. If `NXC_SHADOW_WRITE` is unset, it stops here (read-only) and reports what exists.
3. **`shadow-creds` (add)** — writes a KeyCredential you control and retains the PFX;
   the chain captures the `device_id` and `pfx_path` and prints the exact
   `certipy auth` command to run next.
4. **`shadow-creds` (remove)** — unless `NXC_SHADOW_CLEANUP=0`, removes the
   KeyCredential it just added and records whether cleanup succeeded.

The `shadow_credentials` finding is `success` only when a KeyCredential was staged and
a PFX was produced (`NXC_SHADOW_WRITE=1`); otherwise it is negative and `data` still
lists the existing KeyCredentials. A per-host summary is printed and the full typed
result is saved under `NXC_PATH/playbooks/`.

## Module output (typed)

`shadow-creds` now returns a typed `ResultData` so playbooks read structured fields
instead of parsing logs:

- `action` / `target` / `target_dn` / `is_computer` — what ran, against whom.
- `credentials` — list of `{device_id, creation_time}` for `list`/`info`.
- `device_id` / `pfx_path` — the staged KeyCredential and its PFX (`add`).
- `json_path` — the backup file (`backup`/`revert`).
- `modified` — whether `add`/`remove`/`clear`/`revert` changed the directory.
- `count` / `error`.

Status is `success` when a `list`/`info` finds credentials or a write confirms;
`negative` when nothing is present to list/clear; `failed` on error or a missing
device/account.

## Caveats

- The `add` action is an **active LDAP write** to the target's
  `msDS-KeyCredentialLink`. It is opt-in (`NXC_SHADOW_WRITE=1`) and cleaned up by
  default — leave cleanup on unless you intend to keep the key.
- If cleanup fails, the summary says so; remove the device ID manually with
  `-M shadow-creds -o TARGET=... ACTION=remove DEVICE_ID=...`.
- PKINIT + UnPAC-the-hash is **external** — the chain only stages the key and reports
  the PFX path. It does not authenticate as the target or recover the hash.
- Writing the attribute is directory evidence of the prerequisite; the KDC still has
  to honour PKINIT for the target (certificate mapping / enrollment policy apply).
