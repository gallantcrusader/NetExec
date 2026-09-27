from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import read_registry_value
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    # Reworked by @Defte_ 13/10/2024 to remove unecessary execute operation
    name = "runasppl"
    description = "Check if the registry value RunAsPPL is set or not"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """"""

    @dataclass
    class ResultData:
        present: bool
        value: int | None
        enabled: bool | None

    result_type = ResultData

    def on_admin_login(self, context, connection):
        setting = read_registry_value(connection, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
        enabled = setting.value in (1, 2) if setting.present else None
        if setting.error:
            context.log.fail(setting.error)
        elif setting.present:
            context.log.highlight(f"RunAsPPL registry value: {setting.value} (enabled: {enabled})")
        else:
            context.log.display("RunAsPPL registry value is absent")
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if setting.error else ResultStatus.SUCCESS if enabled else ResultStatus.NEGATIVE,
            self.ResultData(setting.present, setting.value, enabled), error=setting.error,
        )
