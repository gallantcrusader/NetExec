from sys import exit

from nxc.helpers.linked_sql import LinkedSQLData, execute_linked_sql
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Execute commands on linked servers. Module by deathflamingo."""

    name = "exec_on_link"
    description = "Execute commands on a SQL Server linked server"
    supported_protocols = ["mssql"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    result_type = LinkedSQLData

    def options(self, context, module_options):
        """
        LINKED_SERVER    The name of the linked server to execute the command on.
        COMMAND          The SQL batch to execute on the linked server.
        """
        self.linked_server = module_options.get("LINKED_SERVER")
        self.command = module_options.get("COMMAND")
        if not self.linked_server or not self.command:
            context.log.fail("Please specify both LINKED_SERVER and COMMAND options.")
            exit(1)

    def on_login(self, context, connection):
        return execute_linked_sql(context, connection, self.name, self.linked_server, self.command)
