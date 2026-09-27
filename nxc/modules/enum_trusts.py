from nxc.playbooks.results import ActionResult, ResultStatus, RetiredModuleData

from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Extract all Trust Relationships, Trusting Direction, and Trust Transitivity
    Module by Brandon Fisher @shad0wcntr0ller
    """

    name = "enum_trusts"
    description = "[REMOVED] Extract all Trust Relationships, Trusting Direction, and Trust Transitivity"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION
    result_type = RetiredModuleData

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        context.log.fail("[REMOVED] This module moved to the --dc-list LDAP flag.")
        return ActionResult(connection.args.protocol, self.name, connection.host, ResultStatus.FAILED, RetiredModuleData("action:dc_list"), error="[REMOVED] This module moved to the --dc-list LDAP flag.")
