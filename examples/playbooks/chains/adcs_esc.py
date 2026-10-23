"""AD CS ESC survey: enumerate the PKI, flag ESC8, and read certipy's ESC verdicts.

Active Directory Certificate Services misconfigurations (the "ESC" family, ESC1
through ESC16) turn an ordinary domain account into a path to privileged
certificates. This chain is **detection-only**: it surveys the CA estate against a
DC and reports exposure without ever requesting a certificate.

It combines three enumeration modules into one typed verdict:

  1. ``adcs`` (LDAP, typed)        — CA enrollment servers + certificate template
                                      names (does not classify ESCs).
  2. ``enum_ca`` (SMB, typed)      — flags **ESC8** (HTTP web enrollment) on the CA
                                      host. Run against ``host.target`` by default,
                                      or against NXC_ADCS_CA_HOST (needs --allow-target).
  3. ``certipy-find`` (LDAP)       — the authoritative ESC1-ESC16 classifier. Run
                                      with VULN+JSON so it writes its structured
                                      find output to disk; the chain then parses that
                                      JSON for the per-template / per-CA ESC verdicts.

``certipy-find`` is only usable when the ``certipy`` library is importable and a DNS
server is reachable (run nxc with ``--dns-server <DC_IP>``). When it is unavailable
or writes no JSON, the chain still reports ``adcs`` + ``enum_ca`` and notes the gap
rather than failing. It never re-derives ESC logic itself — it only reads what
certipy classified, so the recognised ESCs depend on the installed certipy version.

    export NXC_ADCS_CA_HOST=10.0.0.10            # optional; enum_ca target (--allow-target)
    nxc playbook dc01.example.test examples/playbooks/chains/adcs_esc.py \
        -u USER -p PASS -d example.test --dns-server 10.0.0.10

Configuration (both optional) is read from the environment:

    NXC_ADCS_CA_HOST   host to run enum_ca against instead of the target (--allow-target)

The finding is ``success`` when any ESC is classified (by certipy) or ESC8 web
enrollment is exposed; otherwise ``negative``. The full typed result is saved under
NXC_PATH. Detection only: a vulnerable template is *potential* access, not an
executed compromise.
"""

import json
import os
import re
from dataclasses import dataclass, field

from nxc.paths import NXC_PATH

_ESC_RE = re.compile(r"^ESC\d+$")


@dataclass
class ADCSPosture:
    target: str
    cas: list = field(default_factory=list)                    # CA host/CN strings from adcs
    templates: list = field(default_factory=list)              # template names from adcs
    template_count: int = 0
    web_enrollment_esc8: bool | None = None                    # enum_ca: adcs_found and web_enrollment_found
    web_enrollment_url: str | None = None
    certipy_available: bool = False
    certipy_json_path: str | None = None
    vulnerable_templates: list = field(default_factory=list)   # {name, escs:[...]}
    vulnerable_cas: list = field(default_factory=list)         # {name, escs:[...]}
    esc_summary: list = field(default_factory=list)            # sorted-unique ESC codes
    vulnerable: bool = False
    reason: str | None = None
    evidence_indices: list = field(default_factory=list)


def _env(name, default=None):
    value = os.environ.get(name, "").strip()
    return value or default


def _escs_from(vuln):
    """Pull ESC codes out of certipy's vulnerabilities field (dict or list), defensively."""
    keys = vuln.keys() if isinstance(vuln, dict) else (vuln if isinstance(vuln, list) else [])
    return [str(k) for k in keys if isinstance(k, str) and _ESC_RE.match(k.strip())]


def _entry_name(entry):
    """Find a human name in a certipy entry, whatever the exact key is called."""
    if not isinstance(entry, dict):
        return None
    for key in ("Template Name", "CA Name", "Name", "Display Name"):
        if entry.get(key):
            return str(entry[key])
    for key, value in entry.items():
        if "name" in key.lower() and isinstance(value, (str, int)):
            return str(value)
    return None


def _entry_vulns(entry):
    """Find the vulnerabilities mapping in a certipy entry, whatever the exact key is called."""
    if not isinstance(entry, dict):
        return None
    for key, value in entry.items():
        if "vulnerabilit" in key.lower():
            return value
    return None


def _iter_entries(section):
    """Certipy sections are {index: entry} dicts (or an error string) — yield the entries."""
    if isinstance(section, dict):
        yield from section.values()
    elif isinstance(section, list):
        yield from section


def _parse_certipy_output(output, data):
    """Walk certipy's find output dict; collect ESC verdicts into data. No ESC logic here."""
    if not isinstance(output, dict):
        return
    for top_key, section in output.items():
        low = top_key.lower()
        is_template = "template" in low
        is_ca = "authorit" in low or re.search(r"\bca\b", low)
        if not (is_template or is_ca):
            continue
        for entry in _iter_entries(section):
            escs = _escs_from(_entry_vulns(entry))
            if not escs:
                continue
            record = {"name": _entry_name(entry), "escs": sorted(set(escs))}
            (data.vulnerable_templates if is_template else data.vulnerable_cas).append(record)
    seen = set()
    for record in data.vulnerable_templates + data.vulnerable_cas:
        seen.update(record["escs"])
    if data.web_enrollment_esc8:
        seen.add("ESC8")
    data.esc_summary = sorted(seen, key=lambda s: (len(s), s))


def _print_summary(data):
    lines = ["", "=" * 68, f" {data.target}   AD CS ESC SURVEY", "=" * 68]
    lines.append(f"  CA enrollment servers: {len(data.cas)}")
    lines.extend(f"    - {ca}" for ca in data.cas)
    lines.append(f"  Certificate templates: {data.template_count}")
    esc8 = {True: "yes (ESC8)", False: "no", None: "unknown"}[data.web_enrollment_esc8]
    lines.append(f"  HTTP web enrollment: {esc8}")
    if data.web_enrollment_url:
        lines.append(f"    {data.web_enrollment_url}")
    if data.certipy_available:
        lines.append(f"  certipy classification: {len(data.vulnerable_templates)} template(s), {len(data.vulnerable_cas)} CA(s) vulnerable")
        lines.extend(f"    template {record['name']}: {', '.join(record['escs'])}" for record in data.vulnerable_templates)
        lines.extend(f"    CA {record['name']}: {', '.join(record['escs'])}" for record in data.vulnerable_cas)
    else:
        lines.append("  certipy classification: unavailable (lib missing, DNS, or no JSON written)")
    lines.append("-" * 68)
    if data.vulnerable:
        lines.append(f"  VERDICT: ESC exposure found -> {', '.join(data.esc_summary)}")
    else:
        lines.append(f"  VERDICT: {data.reason or 'no ESC exposure classified'}")
    lines.append("=" * 68)
    print("\n".join(lines), flush=True)


def _certipy_dir_json(before):
    """Newest *.json under the certipy-find output dir not present in `before`."""
    output_dir = os.path.join(NXC_PATH, "modules", "certipy-find")
    try:
        current = {os.path.join(output_dir, name) for name in os.listdir(output_dir) if name.endswith(".json")}
    except OSError:
        return None
    fresh = current - before
    candidates = fresh or current
    if not candidates:
        return None
    return max(candidates, key=lambda path: os.path.getmtime(path))


def _certipy_json_snapshot():
    output_dir = os.path.join(NXC_PATH, "modules", "certipy-find")
    try:
        return {os.path.join(output_dir, name) for name in os.listdir(output_dir) if name.endswith(".json")}
    except OSError:
        return set()


def run(host):
    host.defaults(stop_on_error=False)
    ca_host = _env("NXC_ADCS_CA_HOST")
    data = ADCSPosture(target=host.target)

    with host.evidence() as ev:

        def finish(reason=None):
            if reason is not None:
                data.reason = reason
            data.evidence_indices = list(ev.indices)
            _print_summary(data)
            return host.finding(
                "adcs_esc", ok=data.vulnerable, data=data,
                inputs={"ca_host": ca_host or host.target, "esc_summary": data.esc_summary, "evidence": ev.indices},
            )

        ldap = host.ldap()
        if not ldap.authenticated:
            return finish("Directory authentication was not established")

        # Step 1 — adcs (LDAP, typed): CA enrollment servers + template names.
        adcs = ldap.module("adcs")
        for service in getattr(adcs.data, "services", []) or []:
            attributes = service.get("attributes", {}) if isinstance(service, dict) else {}
            label = attributes.get("dNSHostName") or attributes.get("cn") or attributes.get("distinguishedName")
            if label and label not in data.cas:
                data.cas.append(str(label))
        data.templates = list(getattr(adcs.data, "templates", []) or [])
        data.template_count = len(data.templates)

        # Step 2 — enum_ca (SMB, typed): ESC8 HTTP web enrollment on the CA host.
        enum_session = host.smb()
        enum_note = None
        if ca_host:
            try:
                enum_session = host.at(ca_host).smb()
            except ValueError:
                enum_session = None
                enum_note = f"NXC_ADCS_CA_HOST={ca_host} is outside --allow-target; ESC8 not checked"
        if enum_session is not None:
            eca = enum_session.module("enum_ca")
            adcs_found = bool(getattr(eca.data, "adcs_found", False))
            web_found = bool(getattr(eca.data, "web_enrollment_found", False))
            data.web_enrollment_esc8 = adcs_found and web_found
            data.web_enrollment_url = getattr(eca.data, "enrollment_url", None)

        # Step 3 — certipy-find (LDAP): authoritative ESC1-16 classification via its JSON.
        before = _certipy_json_snapshot()
        certipy = ldap.module("certipy-find", vuln=True, json=True)
        data.certipy_json_path = _certipy_dir_json(before)
        if data.certipy_json_path:
            try:
                with open(data.certipy_json_path) as handle:
                    _parse_certipy_output(json.load(handle), data)
                data.certipy_available = True
            except (OSError, ValueError) as e:
                data.certipy_json_path = None
                enum_note = (enum_note or "") + f" certipy-find JSON could not be parsed: {e}"
        else:
            enum_note = (enum_note or "") + (f" certipy-find produced no JSON: {certipy.error}" if certipy.error else " certipy-find produced no JSON (certipy lib or --dns-server missing)")

        if not data.esc_summary and data.web_enrollment_esc8:
            data.esc_summary = ["ESC8"]
        data.vulnerable = bool(data.esc_summary) or data.web_enrollment_esc8 is True

        if data.vulnerable:
            return finish(enum_note.strip() if enum_note else None)
        if not data.certipy_available and not data.cas:
            return finish((enum_note or "").strip() or "No CA enrollment services found and certipy-find was unavailable")
        if not data.certipy_available:
            return finish((enum_note or "").strip() or "No ESC8 and certipy-find classification unavailable")
        return finish("No ESC vulnerabilities classified and no ESC8 web enrollment")
