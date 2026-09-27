from dataclasses import dataclass
from sys import exit

from impacket.dcerpc.v5 import rrp

from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryWrite, write_registry_value
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Module by @Defte_"""
    name = "remote-uac"
    description = "Enable or disable remote UAC"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    @dataclass
    class ResultData:
        action: str
        registry: RegistryWrite

    result_type = ResultData

    def options(self, context, module_options):
        """
        ACTION  enable or disable (required)
                enable sets LocalAccountTokenFilterPolicy to 0
                disable sets LocalAccountTokenFilterPolicy to 1
        """
        self.action = module_options.get("ACTION", "").lower()
        if self.action not in ("enable", "disable"):
            context.log.fail("ACTION must be enable or disable")
            exit(1)

    def on_admin_login(self, context, connection):
        result = write_registry_value(
            connection, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "LocalAccountTokenFilterPolicy", 0 if self.action == "enable" else 1, rrp.REG_DWORD,
        )
        if result.error:
            context.log.fail(result.error)
        elif result.verified:
            context.log.highlight(f"Remote UAC {self.action} setting verified")
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if result.error or not result.verified else ResultStatus.SUCCESS,
            self.ResultData(self.action, result), error=result.error,
        )
