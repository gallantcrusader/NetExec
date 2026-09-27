from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Enumerate SQL Server linked servers
    Module by deathflamingo, NeffIsBack
    """

    name = "enum_links"
    description = "Enumerate linked SQL Servers and their login configurations."
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        servers: list[dict]
        login_mappings: list[dict]
        login_mappings_queried: bool

    result_type = ResultData

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        servers = []
        mappings = []
        errors = []
        mappings_queried = False
        try:
            servers = connection.conn.sql_query("EXEC sp_linkedservers;") or []
            if connection.conn.lastError:
                errors.append(str(connection.conn.lastError))
            for server in servers:
                context.log.display(f"Linked server: {server['SRV_NAME']}")
            if connection.admin_privs and not errors:
                mappings_queried = True
                mappings = connection.conn.sql_query("EXEC sp_helplinkedsrvlogin") or []
                if connection.conn.lastError:
                    errors.append(str(connection.conn.lastError))
                for mapping in mappings:
                    context.log.display(f"Linked server: {mapping['Linked Server']}")
                    context.log.display(f"  - Local login: {mapping['Local Login']}")
                    context.log.display(f"  - Remote login: {mapping['Remote Login']}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        for error in errors:
            context.log.fail(error)
        if not servers and not errors:
            context.log.display("No linked servers found.")
        return ActionResult(
            "mssql", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if servers or mappings else ResultStatus.NEGATIVE,
            self.ResultData(servers, mappings, mappings_queried), error="; ".join(errors) or None,
        )
