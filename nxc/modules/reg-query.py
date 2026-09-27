from dataclasses import dataclass
from sys import exit

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations

from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryValue
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "reg-query"
    description = "Performs a registry query on the machine"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        operation: str
        path: str
        key: str
        observed: RegistryValue
        requested_value: object
        requested_type: int | None
        completed: bool

    result_type = ResultData

    def options(self, context, module_options):
        """
        PATH    Registry path under HKLM, HKCU, or HKCR (long hive names accepted)
        KEY     Value name to query, set, or delete (empty for the default value)
        VALUE   Value to set; creates a missing value in an existing key
        TYPE    REG_SZ (default), REG_EXPAND_SZ, REG_BINARY, REG_DWORD,
                REG_DWORD_BIG_ENDIAN, REG_LINK, REG_MULTI_SZ, REG_QWORD, REG_NONE
        DELETE  Set true to delete the named value; cannot be combined with VALUE
        """
        self.path = module_options.get("PATH")
        self.key = module_options.get("KEY")
        self.value = module_options.get("VALUE")
        self.delete = module_options.get("DELETE", "false").lower() == "true"
        if not self.path or self.key is None or (self.delete and self.value is not None):
            context.log.fail("PATH and KEY are required; DELETE and VALUE cannot be combined")
            exit(1)
        self.type = None
        if self.value is not None:
            types = {name: getattr(rrp, name) for name in ("REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ", "REG_QWORD")}
            name = module_options.get("TYPE", "REG_SZ").upper()
            if name not in types:
                context.log.fail(f"Unsupported registry type: {name}")
                exit(1)
            self.type = types[name]
            if "WORD" in name:
                try:
                    self.value = int(self.value)
                except ValueError as e:
                    context.log.fail(f"Invalid integer registry value: {e}")
                    exit(1)

    def on_admin_login(self, context, connection):
        operation = "delete" if self.delete else "set" if self.value is not None else "query"
        observed = RegistryValue()
        data = self.ResultData(operation, self.path, self.key, observed, self.value, self.type, False)
        errors = []
        remote_ops = None
        handles = []
        try:
            hive, separator, path = self.path.partition("\\")
            openers = {"HKLM": rrp.hOpenLocalMachine, "HKEY_LOCAL_MACHINE": rrp.hOpenLocalMachine,
                       "HKCU": rrp.hOpenCurrentUser, "HKEY_CURRENT_USER": rrp.hOpenCurrentUser,
                       "HKCR": rrp.hOpenClassesRoot, "HKEY_CLASSES_ROOT": rrp.hOpenClassesRoot}
            if hive.upper() not in openers or not separator:
                raise ValueError(f"Unsupported registry path: {self.path}")
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            rpc = remote_ops._RemoteOperations__rrp
            root = openers[hive.upper()](rpc)["phKey"]
            handles.append(root)
            handle = rrp.hBaseRegOpenKey(rpc, root, path)["phkResult"]
            handles.append(handle)
            try:
                observed.registry_type, observed.value = rrp.hBaseRegQueryValue(rpc, handle, self.key)
                observed.present = True
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() != 2:
                    raise
            if operation == "set":
                rrp.hBaseRegSetValue(rpc, handle, self.key, self.type, self.value)
                data.completed = True
                context.log.success(f"Set {self.path}\\{self.key}")
            elif operation == "delete" and observed.present:
                rrp.hBaseRegDeleteValue(rpc, handle, self.key)
                data.completed = True
                context.log.success(f"Deleted {self.path}\\{self.key}")
            elif operation == "query" and observed.present:
                data.completed = True
                context.log.highlight(f"{self.key}: {observed.value}")
        except rrp.DCERPCSessionError as e:
            if e.get_error_code() != 2 or operation == "set":
                errors.append(str(e) or type(e).__name__)
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
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if data.completed else ResultStatus.NEGATIVE,
            data, error="; ".join(errors) or None,
        )
