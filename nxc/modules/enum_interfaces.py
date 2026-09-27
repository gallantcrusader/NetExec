from dataclasses import dataclass

from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5 import rrp

from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryValue
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Registry network interface inventory, originally by Sant0rryu and NeffIsBack."""

    name = "enum_interfaces"
    description = "Retrieve network interface settings from remote Windows registry (formerly --interfaces)"
    supported_protocols = ["smb"]
    opsec_safe = False
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        interfaces: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        """No options available"""

    def read_value(self, rpc, handle, name):
        value = RegistryValue()
        try:
            value.registry_type, value.value = rrp.hBaseRegQueryValue(rpc, handle, name)
            value.present = True
        except rrp.DCERPCSessionError as e:
            if e.get_error_code() != 2:
                value.error = str(e) or type(e).__name__
        except Exception as e:
            value.error = str(e) or type(e).__name__
        return value

    def on_admin_login(self, context, connection):
        interfaces = []
        errors = []
        handles = []
        remote_ops = None
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            rpc = remote_ops._RemoteOperations__rrp
            root = rrp.hOpenLocalMachine(rpc)["phKey"]
            handles.append(root)
            base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            key = rrp.hBaseRegOpenKey(rpc, root, base)["phkResult"]
            handles.append(key)
            count = rrp.hBaseRegQueryInfoKey(rpc, key)["lpcSubKeys"]
            for index in range(count):
                identifier = rrp.hBaseRegEnumKey(rpc, key, index)["lpNameOut"].rstrip("\x00")
                interface = {"id": identifier, "values": {}, "name": RegistryValue(), "error": None}
                interfaces.append(interface)
                try:
                    handle = rrp.hBaseRegOpenKey(rpc, root, base + "\\" + identifier)["phkResult"]
                    handles.append(handle)
                    for name in ("EnableDHCP", "IPAddress", "SubnetMask", "DefaultGateway", "DhcpIPAddress", "DhcpSubnetMask", "DhcpDefaultGateway"):
                        value = self.read_value(rpc, handle, name)
                        interface["values"][name] = value
                        if value.error:
                            errors.append(f"{identifier} {name}: {value.error}")
                    name_key = rf"SYSTEM\CurrentControlSet\Control\Network\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{identifier}\Connection"
                    try:
                        name_handle = rrp.hBaseRegOpenKey(rpc, root, name_key)["phkResult"]
                        handles.append(name_handle)
                        interface["name"] = self.read_value(rpc, name_handle, "Name")
                    except rrp.DCERPCSessionError as e:
                        if e.get_error_code() != 2:
                            raise
                    if interface["name"].error:
                        errors.append(f"{identifier} Name: {interface['name'].error}")
                    context.log.highlight(f"{identifier}: {interface['name'].value}")
                    for name, value in interface["values"].items():
                        if value.present:
                            context.log.highlight(f"  {name}: {value.value}")
                except Exception as e:
                    interface["error"] = str(e) or type(e).__name__
                    errors.append(f"{identifier}: {interface['error']}")
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
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if interfaces else ResultStatus.NEGATIVE,
            self.ResultData(interfaces), error="; ".join(errors) or None,
        )
