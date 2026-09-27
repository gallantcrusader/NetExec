from dataclasses import dataclass, field
from sys import exit

from impacket.ldap.ldapasn1 import Scope
from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes, sid_to_str
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Read AD's computed transitive group SIDs for one user or computer."""

    name = "token-groups"
    description = "Read computed tokenGroups and SID history for one AD user/computer"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        principal: str
        dn: str | None = None
        principal_sid: str | None = None
        group_sids: list[str] = field(default_factory=list)
        sid_history: list[str] = field(default_factory=list)
        directory_sids: list[str] = field(default_factory=list)
        attributes: dict = field(default_factory=dict)
        groups_returned: bool = False

    result_type = ResultData

    def options(self, context, module_options):
        """PRINCIPAL    Exact sAMAccountName of a user/computer to query."""
        self.principal = module_options.get("PRINCIPAL")
        if not self.principal:
            context.log.fail("PRINCIPAL is required")
            exit(1)

    def decode_sids(self, values):
        values = values if isinstance(values, list) else [values]
        sids = []
        for raw in values:
            if not isinstance(raw, bytes) or len(raw) < 8 or raw[0] != 1 or len(raw) != 8 + 4 * raw[1]:
                raise ValueError("LDAP returned a malformed binary SID")
            sids.append(sid_to_str(raw))
        return sids

    def on_login(self, context, connection):
        data = self.ResultData(self.principal)
        errors = []
        found = parse_result_attributes(connection.search(
            f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(self.principal)}))",
            ["distinguishedName", "objectSid"],
        ))
        if connection.last_search_error:
            errors.append(connection.last_search_error)
        elif not found:
            return ActionResult("ldap", self.name, connection.host, ResultStatus.NEGATIVE, data)
        elif len(found) != 1 or not found[0].get("distinguishedName") or not isinstance(found[0].get("objectSid"), str):
            errors.append("Principal did not resolve to one user/computer with a SID and DN")
        if not errors:
            data.dn = found[0]["distinguishedName"]
            data.principal_sid = found[0]["objectSid"]
            original_scope = connection.scope
            try:
                connection.scope = Scope("baseObject")
                rows = parse_result_attributes(connection.search("(objectClass=*)", ["tokenGroups", "sIDHistory", "primaryGroupID", "objectSid"], baseDN=data.dn))
            finally:
                connection.scope = original_scope
            if connection.last_search_error:
                errors.append(connection.last_search_error)
            if len(rows) == 1:
                data.attributes = rows[0]
                data.groups_returned = "tokenGroups" in rows[0]
                # Validate binary SID payloads separately from LDAP attribute parsing.
                try:
                    data.group_sids = self.decode_sids(rows[0].get("tokenGroups", []))
                    data.sid_history = self.decode_sids(rows[0].get("sIDHistory", []))
                    data.directory_sids = list(dict.fromkeys([data.principal_sid, *data.group_sids, *data.sid_history]))
                except ValueError as e:
                    errors.append(str(e))
            else:
                errors.append("BASE query did not return exactly one principal")
            if not data.groups_returned:
                errors.append("tokenGroups was not returned; transitive group membership is unverified")
        for sid in data.group_sids:
            context.log.highlight(sid)
        for error in errors:
            context.log.fail(error)
        return ActionResult("ldap", self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS, data, error="; ".join(errors) or None)
