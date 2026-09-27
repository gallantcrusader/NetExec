from sys import exit

from nxc.helpers.misc import CATEGORY
from nxc.helpers.sql_configuration import SQLConfigurationData, change_cmdshell


class NXCModule:
    """Enable or disable xp_cmdshell in MSSQL Server. Module by crosscutsaw."""

    name = "enable_cmdshell"
    description = "Enable or disable xp_cmdshell in MSSQL Server"
    supported_protocols = ["mssql"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    result_type = SQLConfigurationData

    def options(self, context, module_options):
        """ACTION      enable or disable xp_cmdshell (required)"""
        self.action = module_options.get("ACTION", "").lower()
        if self.action not in ("enable", "disable"):
            context.log.fail("ACTION must be enable or disable")
            exit(1)

    def on_login(self, context, connection):
        return change_cmdshell(context, connection, self.name, self.action)
