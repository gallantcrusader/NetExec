from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryValue, read_registry_value
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "install_elevated"
    description = "Checks for AlwaysInstallElevated"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        machine: RegistryValue
        current_user: RegistryValue | None
        enabled: bool | None

    result_type = ResultData

    def options(self, context, module_options):
        """No options available."""

    def on_admin_login(self, context, connection):
        key = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
        machine = read_registry_value(connection, key, "AlwaysInstallElevated")
        current_user = None
        enabled = None
        errors = [machine.error] if machine.error else []
        if not machine.error:
            enabled = False
            if machine.present and machine.value == 1:
                current_user = read_registry_value(connection, key, "AlwaysInstallElevated", hive="HKCU")
                if current_user.error:
                    errors.append(current_user.error)
                    enabled = None
                else:
                    enabled = current_user.present and current_user.value == 1
        if errors:
            context.log.fail("; ".join(errors))
        elif enabled:
            context.log.highlight("AlwaysInstallElevated Status: 1 (Enabled)")
        elif machine.present and machine.value == 1:
            context.log.highlight("AlwaysInstallElevated Status: 1 (Enabled: Computer Only)")
        else:
            context.log.highlight("AlwaysInstallElevated Status: 0 (Disabled)")
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if enabled else ResultStatus.NEGATIVE,
            self.ResultData(machine, current_user, enabled), error="; ".join(errors) if errors else None,
        )
