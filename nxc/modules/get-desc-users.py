from dataclasses import dataclass
import re
from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Get description of users
    Module by @nodauf
    """

    name = "get-desc-users"
    description = "Get description of the users. May contain password"
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        users: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        """
        FILTER    Apply the FILTER (grep-like) (default: '')
        PASSWORDPOLICY    Is the windows password policy enabled ? (default: False)
        MINLENGTH    Minimum password length to match, only used if PASSWORDPOLICY is True (default: 6)
        """
        self.FILTER = ""
        self.MINLENGTH = "6"
        self.PASSWORDPOLICY = False
        if "FILTER" in module_options:
            self.FILTER = module_options["FILTER"]
        if "MINLENGTH" in module_options:
            self.MINLENGTH = module_options["MINLENGTH"]
        if str(module_options.get("PASSWORDPOLICY", "false")).lower() in {"true", "1", "yes"}:
            self.PASSWORDPOLICY = True
            self.regex = re.compile(r"((?=[^ ]*[A-Z])(?=[^ ]*[a-z])(?=[^ ]*\d)|(?=[^ ]*[a-z])(?=[^ ]*\d)(?=[^ ]*[^\w \n])|(?=[^ ]*[A-Z])(?=[^ ]*\d)(?=[^ ]*[^\w \n])|(?=[^ ]*[A-Z])(?=[^ ]*[a-z])(?=[^ ]*[^\w \n]))[^ \n]{" + self.MINLENGTH + ",}$")  # Credit : https://stackoverflow.com/questions/31191248/regex-password-must-have-at-least-3-of-the-4-of-the-following

    def on_login(self, context, connection):
        """Concurrent. Required if on_admin_login is not present. This gets called on each authenticated connection"""
        # Building the search filter
        searchFilter = "(objectclass=user)"

        resp = connection.search(searchFilter, ["sAMAccountName", "description"])

        context.log.debug(f"Total of records returned {len(resp)}")
        resp_parsed = parse_result_attributes(resp)
        answers = [[x["sAMAccountName"], x.get("description")] for x in resp_parsed if x.get("description")]

        answers = self.filter_answer(context, answers)
        if len(answers) > 0:
            context.log.success("Found following users: ")
            for answer in answers:
                context.log.highlight(f"User: {answer[0]:<20} description: {answer[1]}")

        error = connection.last_search_error
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if error else ResultStatus.SUCCESS if answers else ResultStatus.NEGATIVE,
            self.ResultData([{"username": username, "description": description} for username, description in answers]),
            error=error,
        )

    def filter_answer(self, context, answers):
        filtered = []
        for username, description in answers:
            if self.FILTER and self.FILTER not in str(description):
                continue
            if self.PASSWORDPOLICY and not self.regex.search(str(description)):
                continue
            filtered.append([username, description])
        return filtered
