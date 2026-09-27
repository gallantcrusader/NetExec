from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryValue, read_registry_value
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Read LmCompatibilityLevel. Originally by Tw1sm; modified by Deft."""

    name = "ntlmv1"
    description = "Read the configured LmCompatibilityLevel registry value"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        registry: RegistryValue

    result_type = ResultData

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        value = read_registry_value(connection, r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel")
        if value.error:
            context.log.fail(value.error)
        elif value.present:
            context.log.highlight(f"Configured LmCompatibilityLevel: {value.value}")
        else:
            context.log.display("LmCompatibilityLevel is not explicitly configured in this registry value")
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if value.error else ResultStatus.SUCCESS if value.present else ResultStatus.NEGATIVE,
            self.ResultData(value), error=value.error,
        )
