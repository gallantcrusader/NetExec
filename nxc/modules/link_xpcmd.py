from sys import exit

from nxc.helpers.linked_sql import LinkedSQLData, execute_linked_sql
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Run xp_cmdshell commands on a linked SQL server. Module by deathflamingo."""

    name = "link_xpcmd"
    description = "Run xp_cmdshell commands on a linked SQL server"
    supported_protocols = ["mssql"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    result_type = LinkedSQLData

    def options(self, context, module_options):
        """
        LINKED_SERVER    The name of the linked SQL server to target.
        CMD              The command to run via xp_cmdshell.
        """
        self.linked_server = module_options.get("LINKED_SERVER")
        self.command = module_options.get("CMD")
        if not self.linked_server or not self.command:
            context.log.fail("Please provide both LINKED_SERVER and CMD options.")
            exit(1)

    def on_login(self, context, connection):
        return execute_linked_sql(context, connection, self.name, self.linked_server, self.command, xp_cmdshell=True)
