from dataclasses import dataclass

from impacket import tds
from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Module written by @Defte_"""
    name = "mssql_cbt"
    description = "Checks whether MSSQL accepts authentication with an empty Channel Binding Token"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        tls_required: bool | None
        attempted: bool = False
        authenticated_without_cbt: bool | None = None
        cbt_required: bool | None = None
        reason: str | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        data = self.ResultData(connection.encryption)
        if connection.encryption is not True or connection.args.local_auth:
            data.reason = "Windows authentication is required for this check" if connection.args.local_auth else "TLS requirement was not established" if connection.encryption is None else "Server does not require TLS; CBT policy was not tested"
            context.log.display(data.reason)
            return ActionResult("mssql", self.name, connection.host, ResultStatus.SKIPPED, data)

        new_conn = None
        errors = []
        try:
            new_conn = tds.MSSQL(connection.host, connection.port, connection.conn.remoteName)
            new_conn.connect(connection.args.mssql_timeout)
            data.attempted = True
            if connection.kerberos:
                success = new_conn.kerberosLogin(
                    None,
                    connection.username,
                    connection.password,
                    connection.targetDomain,
                    f"{connection.lmhash}:{connection.nthash}" if connection.lmhash or connection.nthash else None,
                    connection.aesKey,
                    connection.kdcHost,
                    None,
                    None,
                    connection.use_kcache,
                    cbt_fake_value=b""
                )
            else:
                success = new_conn.login(
                    None,
                    connection.username,
                    connection.password,
                    connection.targetDomain,
                    f"{connection.lmhash}:{connection.nthash}" if connection.lmhash or connection.nthash else None,
                    not connection.args.local_auth,
                    cbt_fake_value=b""
                )
            data.authenticated_without_cbt = bool(success)
            if success:
                data.cbt_required = False
                context.log.highlight("Authentication with empty Channel Binding Token succeeded")
            else:
                data.reason = "Authentication with empty CBT was rejected; rejection alone does not establish CBT policy"
                errors.append(data.reason)
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        finally:
            if new_conn is not None:
                try:
                    new_conn.disconnect()
                except Exception as e:
                    errors.append(f"Closing CBT test connection: {e}")
        for error in errors:
            context.log.fail(error)
        return ActionResult(
            "mssql", self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS,
            data, error="; ".join(errors) or None,
        )
