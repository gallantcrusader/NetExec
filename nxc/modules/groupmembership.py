from dataclasses import dataclass
from sys import exit

from ldap3.utils.conv import escape_filter_chars
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Created as a contributtion from HackTheBox Academy team for CrackMapExec
    Reference: https://academy.hackthebox.com/module/details/84

    Module by @juliourena
    Based on: https://github.com/juliourena/CrackMapExec/blob/master/cme/modules/get_description.py
    """

    name = "groupmembership"
    description = "Query the groups to which a user belongs."
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        username: str
        user_found: bool
        groups: list[str]
        primary_group_id: int | None
        primary_group: str | None

    result_type = ResultData

    def options(self, context, module_options):
        """USER    Choose a username to query group membership"""
        if not module_options.get("USER"):
            context.log.fail("Missing USER option, use --options to list available parameters")
            exit(1)
        self.user = module_options["USER"]

    def on_login(self, context, connection):
        entries = parse_result_attributes(connection.search(
            f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(self.user)}))",
            ["memberOf", "primaryGroupID", "objectSid"],
        ))
        errors = [connection.last_search_error] if connection.last_search_error else []
        groups = []
        primary_group_id = None
        primary_group = None
        if entries:
            user = entries[0]
            memberships = user.get("memberOf", [])
            groups = list(dict.fromkeys(memberships if isinstance(memberships, list) else [memberships]))
            if user.get("primaryGroupID") is not None:
                primary_group_id = int(user["primaryGroupID"])
                if user.get("objectSid"):
                    primary_sid = f'{user["objectSid"].rsplit("-", 1)[0]}-{primary_group_id}'
                    primary = parse_result_attributes(connection.search(
                        f"(&(objectClass=group)(objectSid={escape_filter_chars(primary_sid)}))", ["distinguishedName"],
                    ))
                    if connection.last_search_error:
                        errors.append(connection.last_search_error)
                    if primary:
                        primary_group = primary[0]["distinguishedName"]
                        if primary_group not in groups:
                            groups.append(primary_group)
        if groups:
            context.log.success(f"User: {self.user} is member of following groups: ")
            for group in groups:
                context.log.highlight(group)
        elif not entries:
            context.log.display(f"User not found: {self.user}")
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if groups else ResultStatus.NEGATIVE,
            self.ResultData(self.user, bool(entries), groups, primary_group_id, primary_group),
            error="; ".join(errors) if errors else None,
        )
