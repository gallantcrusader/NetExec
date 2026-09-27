import json
from dataclasses import dataclass, field
from pathlib import Path
from os.path import isfile
from sys import exit
from uuid import uuid4

from impacket.ldap.ldapasn1 import SDFlagsControl, Scope
from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.helpers.security_descriptor import descriptor_evidence
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus


class NXCModule:
    """Read ordered DACL evidence; ACE matches do not establish effective access."""

    name = "daclread"
    description = "Read or back up object DACLs, preserving raw descriptors and ordered ACE evidence"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        objects: list[dict] = field(default_factory=list)
        principal: str | None = None
        principal_sid: str | None = None
        missing_targets: list[str] = field(default_factory=list)

    result_type = ResultData
    rights_guids = {
        "ResetPassword": {"00299570-246d-11d0-a768-00aa006e0529"},
        "WriteMembers": {"bf9679c0-0de6-11d0-a285-00aa003049e2"},
        "DCSync": {"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"},
    }

    def options(self, context, module_options):
        """
        TARGET          Target sAMAccountName, or a file of names.
        TARGET_DN       Target distinguishedName, or a file of DNs.
        PRINCIPAL       Filter matches by this trustee sAMAccountName.
        PRINCIPAL_SID   Filter matches by a known trustee SID (for built-in identities).
        ACTION          read (default) or backup; backups go under NXC_PATH/logs/daclread.
        ACE_TYPE        allowed (default), denied, or all.
        RIGHTS          FullControl, ResetPassword, WriteMembers, or DCSync.
        RIGHTS_GUID     Object-specific right GUID to match.

        Full ACE evidence is retained regardless of filters. Matches are not an
        effective-access calculation and do not expand group membership.
        """
        self.targets = []
        for option, attribute in (("TARGET", "sAMAccountName"), ("TARGET_DN", "distinguishedName")):
            if module_options.get(option):
                value = str(module_options[option])
                path = Path(value)
                values = path.read_text(encoding="utf-8").splitlines() if isfile(value) else [value]
                self.targets.extend((value.strip(), attribute) for value in values if value.strip())
        self.principal = module_options.get("PRINCIPAL")
        self.principal_sid = module_options.get("PRINCIPAL_SID")
        self.action = module_options.get("ACTION", "read").lower()
        self.ace_type = module_options.get("ACE_TYPE", "allowed").lower()
        self.rights = module_options.get("RIGHTS")
        self.rights_guid = module_options.get("RIGHTS_GUID", "").lower() or None
        if not self.targets or (self.principal and self.principal_sid) or self.action not in ("read", "backup") or self.ace_type not in ("allowed", "denied", "all") or self.rights not in (None, "FullControl", *self.rights_guids):
            context.log.fail("Specify TARGET/TARGET_DN, one trustee filter, and valid ACTION, ACE_TYPE, and RIGHTS options; see --options")
            exit(1)

    def matches(self, ace, sid):
        if not ace["supported"]:
            return False
        if self.ace_type != "all" and ace["access"] != self.ace_type:
            return False
        if sid is not None and ace["trustee_sid"] != sid:
            return False
        if self.rights_guid and ace["object_type"] != self.rights_guid:
            return False
        if self.rights == "FullControl" and not (ace["mask"] & 0x10000000 or ace["mask"] & 0xF01FF == 0xF01FF):
            return False
        return self.rights not in self.rights_guids or ace["object_type"] in self.rights_guids[self.rights]

    def on_login(self, context, connection):
        data = self.ResultData(principal=self.principal or self.principal_sid, principal_sid=self.principal_sid)
        errors = []
        artifacts = []
        if self.principal:
            principals = parse_result_attributes(connection.search(f"(sAMAccountName={escape_filter_chars(self.principal)})", ["objectSid"]))
            if connection.last_search_error:
                errors.append(connection.last_search_error)
            elif len(principals) != 1 or not isinstance(principals[0].get("objectSid"), str):
                errors.append(f"Principal {self.principal} did not resolve to one SID")
            else:
                data.principal_sid = principals[0]["objectSid"]
        for target, attribute in self.targets:
            if errors:
                break
            search_filter = f"({attribute}={escape_filter_chars(target)})" if attribute == "sAMAccountName" else "(objectClass=*)"
            original_scope = getattr(connection, "scope", None)
            try:
                if attribute == "distinguishedName":
                    connection.scope = Scope("baseObject")
                rows = parse_result_attributes(connection.search(
                    search_filter,
                    ["distinguishedName", "sAMAccountName", "objectSid", "nTSecurityDescriptor"],
                    searchControls=[SDFlagsControl(criticality=True, flags=0x07)],
                    **({"baseDN": target} if attribute == "distinguishedName" else {}),
                ))
            finally:
                connection.scope = original_scope
            if connection.last_search_error:
                errors.append(connection.last_search_error)
            if not rows:
                if not errors:
                    data.missing_targets.append(target)
                continue
            for row in rows:
                record = {"target": target, "dn": row.get("distinguishedName"), "name": row.get("sAMAccountName"), "sid": row.get("objectSid"), "descriptor": None, "matches": [], "error": None}
                data.objects.append(record)
                raw = row.get("nTSecurityDescriptor")
                if not isinstance(raw, bytes):
                    record["error"] = "Security descriptor was not returned as bytes (missing or unreadable)"
                    errors.append(record["error"])
                    break
                # Binary descriptor decoding and filesystem export can fail.
                # Ordinary LDAP search/attribute parsing stays outside this block.
                try:
                    record["descriptor"] = {"raw": raw}
                    record["descriptor"] = descriptor_evidence(raw)
                    record["matches"] = [ace["index"] for ace in record["descriptor"]["aces"] if self.matches(ace, data.principal_sid)]
                    context.log.highlight(f"{record['dn']}: {len(record['matches'])} matching ACEs")
                    for index in record["matches"]:
                        ace = record["descriptor"]["aces"][index]
                        context.log.highlight(f"ACE[{index}] {ace['access']} {ace['trustee_sid']} mask=0x{ace['mask']:x} flags=0x{ace['flags']:x} object={ace['object_type']}")
                    if self.action == "backup":
                        folder = Path(NXC_PATH) / "logs" / "daclread"
                        folder.mkdir(parents=True, exist_ok=True)
                        path = folder / f"dacledit-{uuid4().hex}.bak"
                        path.write_text(json.dumps({"sd": raw.hex(), "dn": record["dn"]}), encoding="utf-8")
                        artifacts.append(Artifact(path, "security_descriptor"))
                        context.log.highlight(f"DACL backed up to {path}")
                except Exception as e:
                    record["error"] = str(e) or type(e).__name__
                    errors.append(record["error"])
                    break
        for error in errors:
            context.log.fail(error)
        found = bool(artifacts) or any(record["matches"] for record in data.objects)
        return ActionResult("ldap", self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if found else ResultStatus.NEGATIVE, data, artifacts=artifacts, error="; ".join(errors) or None)
