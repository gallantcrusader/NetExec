from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Enumerate SQL Server impersonation permission records
    Module by deathflamingo
    """

    name = "enum_impersonate"
    description = "Enumerate server impersonation permission records"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        permissions: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        permissions = []
        error = None
        try:
            permissions = connection.conn.sql_query("""
                SELECT p.permission_name, p.state_desc, p.class_desc,
                       p.grantee_principal_id, grantee.name AS grantee,
                       p.grantor_principal_id, grantor.name AS grantor,
                       p.major_id, target.name AS target_login
                FROM sys.server_permissions p
                LEFT JOIN sys.server_principals grantee
                  ON p.grantee_principal_id = grantee.principal_id
                LEFT JOIN sys.server_principals grantor
                  ON p.grantor_principal_id = grantor.principal_id
                LEFT JOIN sys.server_principals target
                  ON p.class = 101 AND p.major_id = target.principal_id
                WHERE p.permission_name LIKE 'IMPERSONATE%'
                ORDER BY grantee.name, p.permission_name, target.name;
            """) or []
            if connection.conn.lastError:
                error = str(connection.conn.lastError)
            for permission in permissions:
                context.log.display(f"{permission['grantee']} - {permission['state_desc']} {permission['permission_name']} - target: {permission['target_login']} - grantor: {permission['grantor']}")
        except Exception as e:
            error = str(e) or type(e).__name__
        if error:
            context.log.fail(error)
        elif not permissions:
            context.log.display("No visible server impersonation permission records found.")
        return ActionResult(
            "mssql", self.name, connection.host,
            ResultStatus.FAILED if error else ResultStatus.SUCCESS if permissions else ResultStatus.NEGATIVE,
            self.ResultData(permissions), error=error,
        )
