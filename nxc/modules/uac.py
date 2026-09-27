
from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import read_registry_value
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "uac"
    description = "Checks UAC status"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """ """

    @dataclass
    class ResultData:
        present: bool
        value: int | None
        enabled: bool | None

    result_type = ResultData

    def on_admin_login(self, context, connection):
        setting = read_registry_value(connection, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        enabled = setting.value in (1,) if setting.present else None
        if setting.error:
            context.log.fail(setting.error)
        elif setting.present:
            context.log.highlight(f"UAC registry value: {setting.value} (enabled: {enabled})")
        else:
            context.log.display("EnableLUA registry value is absent")
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if setting.error else ResultStatus.SUCCESS if enabled else ResultStatus.NEGATIVE,
            self.ResultData(setting.present, setting.value, enabled), error=setting.error,
        )
