from dataclasses import dataclass
from sys import exit

from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Executes the Test-Connection PowerShell cmdlet
    Module by @byt3bl33d3r
    """

    name = "test_connection"
    description = "Pings a host"
    supported_protocols = ["smb", "mssql"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        destination: str
        reachable: bool | None
        output: object

    result_type = ResultData

    def options(self, context, module_options):
        """HOST      Host to ping"""
        self.host = None

        if "HOST" not in module_options:
            context.log.fail("HOST option is required!")
            exit(1)

        self.host = module_options["HOST"]

    def on_admin_login(self, context, connection):
        destination = self.host.replace("'", "''")
        command = f"$ProgressPreference = 'SilentlyContinue'; Test-Connection -ComputerName '{destination}' -Quiet -Count 1"
        output = None
        reachable = None
        error = None
        try:
            response = connection.ps_execute(command, get_output=True)
            output = response[0] if isinstance(response, (list, tuple)) and len(response) == 1 else response
            text = output.decode("utf-8").strip() if isinstance(output, bytes) else str(output).strip()
            if text.casefold() in ("true", "false"):
                reachable = text.casefold() == "true"
                if reachable:
                    context.log.success("Pinged successfully")
                else:
                    context.log.display("Test-Connection reported unreachable")
            else:
                error = "Test-Connection did not return a Boolean result"
        except Exception as e:
            error = str(e) or type(e).__name__
        if error:
            context.log.fail(error)
        return ActionResult(
            connection.args.protocol, self.name, connection.host,
            ResultStatus.FAILED if error else ResultStatus.SUCCESS if reachable else ResultStatus.NEGATIVE,
            self.ResultData(self.host, reachable, output), error=error,
        )
