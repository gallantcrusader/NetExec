from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryValue, read_registry_value
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Module by @joaovarelas"""

    name = "hyperv-host"
    description = "Performs a registry query on the VM to lookup its HyperV Host"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        hostname: str | None
        registry: RegistryValue

    result_type = ResultData

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        value = read_registry_value(connection, r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", "HostName")
        hostname = value.value.rstrip("\x00") if isinstance(value.value, str) else None
        if value.error:
            context.log.fail(value.error)
        elif value.present:
            context.log.highlight(f"HostName: {value.value}")
        else:
            context.log.display("Hyper-V host registry value is absent")
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if value.error else ResultStatus.SUCCESS if value.present else ResultStatus.NEGATIVE,
            self.ResultData(hostname, value), error=value.error,
        )
