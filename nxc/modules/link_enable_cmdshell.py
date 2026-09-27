from sys import exit

from nxc.helpers.misc import CATEGORY
from nxc.helpers.sql_configuration import SQLConfigurationData, change_cmdshell


class NXCModule:
    """Enable or disable xp_cmdshell on a linked server. Module by deathflamingo."""

    name = "link_enable_cmdshell"
    description = "Enable or disable xp_cmdshell on a linked MSSQL server"
    supported_protocols = ["mssql"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    result_type = SQLConfigurationData

    def options(self, context, module_options):
        """
        ACTION           enable (default) or disable xp_cmdshell
        LINKED_SERVER    The name of the linked SQL server to target (required)
        """
        self.action = module_options.get("ACTION", "enable").lower()
        self.linked_server = module_options.get("LINKED_SERVER")
        if self.action not in ("enable", "disable") or not self.linked_server:
            context.log.fail("Specify LINKED_SERVER and an ACTION of enable or disable")
            exit(1)

    def on_login(self, context, connection):
        return change_cmdshell(context, connection, self.name, self.action, self.linked_server)
