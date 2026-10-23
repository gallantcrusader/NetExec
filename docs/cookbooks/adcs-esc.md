# AD CS ESC survey

`examples/playbooks/chains/adcs_esc.py` surveys an Active Directory Certificate
Services estate for the ESC misconfiguration family (ESC1–ESC16) and folds the
result into one typed `adcs_esc` verdict. (For the individual modules, see
[adcs](adcs.md), [enum_ca](enum_ca.md), and [certipy-find](certipy-find.md).)

This is a **detection-only** chain. It enumerates CAs, templates, web enrollment,
and certipy's ESC classification; it never requests a certificate and never writes
to the directory. Point it at a **DC**.

## Background

AD CS exposes a set of privilege-escalation primitives collectively called ESC1
through ESC16 — enrollee-supplied subjects, dangerous template ACLs, NTLM relay to
web enrollment, vulnerable CA settings, and so on. NetExec classifies two sources:

- **ESC8** (HTTP web enrollment) is flagged directly by the typed `enum_ca` module,
  which probes the CA host's `certsrv` endpoint over RPC + HTTP.
- The **full ESC1–ESC16 classification** comes from `certipy-find`, which wraps the
  external `certipy` library. The chain runs it with `VULN=true JSON=true` so it
  writes its structured find output to disk, then parses that JSON for the
  per-template and per-CA ESC verdicts. The chain does not re-implement ESC logic —
  it only reads what certipy classified.

## The three steps

1. **`adcs` (LDAP, typed)** — lists PKI enrollment services and certificate template
   names. Populates `cas` (derived from each service's `dNSHostName`/`cn`) and
   `templates` / `template_count`.
2. **`enum_ca` (SMB, typed)** — flags ESC8. Runs against `host.target` by default,
   or against `NXC_ADCS_CA_HOST` via `host.at(...)` when set. Records
   `web_enrollment_esc8` (`adcs_found and web_enrollment_found`) and
   `web_enrollment_url`.
3. **`certipy-find` (LDAP)** — run with `vuln=True, json=True`. The chain locates the
   newest `*.json` written under `<NXC_PATH>/modules/certipy-find/` during this step
   and parses it into `vulnerable_templates` (`{name, escs}`),
   `vulnerable_cas` (`{name, escs}`), and a sorted-unique `esc_summary`.

## Configuration

| Variable | Meaning |
| --- | --- |
| `NXC_ADCS_CA_HOST` | host to run `enum_ca` against instead of the target (needs `--allow-target`) |

```sh
export NXC_ADCS_CA_HOST=10.0.0.10
nxc playbook dc01.example.test examples/playbooks/chains/adcs_esc.py \
    -u USER -p PASS -d example.test --dns-server 10.0.0.10 --allow-target 10.0.0.10
```

## Requirements

- `certipy-find` needs the `certipy` library importable in the venv and a reachable
  DNS server — run nxc with `--dns-server <DC_IP>`. When certipy is missing, DNS
  fails, or no JSON is written, the chain sets `certipy_available=False`, still
  reports `adcs` + `enum_ca`, and notes the gap in `reason` rather than failing.

## Result and caveats

The `adcs_esc` finding is `success` when any ESC is classified **or** ESC8 web
enrollment is exposed; otherwise `negative`. `data` carries `cas`, `templates`,
`template_count`, `web_enrollment_esc8`, `web_enrollment_url`, `certipy_available`,
`certipy_json_path`, `vulnerable_templates`, `vulnerable_cas`, `esc_summary`,
`vulnerable`, and `reason`.

- **Detection only.** A vulnerable template is *potential* access, not an executed
  compromise — no certificate is requested and nothing is relayed.
- **Typed vs parsed.** `adcs` and `enum_ca` are typed modules read via their dataclass
  results; `certipy-find` has no typed result, so the chain parses its JSON output.
- **certipy version matters.** Which ESCs are recognised depends on the installed
  `certipy` version, and its output dict shape varies between versions, so the chain
  parses it defensively (it walks the structure rather than assuming fixed keys).
