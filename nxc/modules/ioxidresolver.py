# Credit to https://airbus-cyber-security.com/fr/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/
# Airbus CERT
# module by @mpgn_x64
# updated by @NeffIsBack

from dataclasses import dataclass
from ipaddress import ip_address
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import IObjectExporter, IID_IObjectExporter
from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "ioxidresolver"
    description = "This module helps you to identify hosts that have additional active interfaces"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        addresses: list[str]
        bindings: list[dict]
        different_only: bool

    result_type = ResultData

    def options(self, context, module_options):
        """DIFFERENT show only ip address if different from target ip (Default: False)"""
        self.pivot = module_options.get("DIFFERENT", "false").lower() in ["true", "1"]

    def on_login(self, context, connection):
        addresses = []
        bindings = []
        errors = []
        portmap = None
        try:
            target_address = str(ip_address(connection.host))
        except ValueError as e:
            context.log.debug(f"Target is not an IP literal: {e}")
            target_address = connection.host
        try:
            portmap = NXCRPCConnection(connection, force_tcp=True).connect(
                None, IID_IObjectExporter, target_ip=connection.host,
                auth_level=RPC_C_AUTHN_LEVEL_NONE, anonymous_rpc=True,
            )
            for binding in IObjectExporter(portmap).ServerAlive2():
                address = binding["aNetworkAddr"].rstrip("\x00")
                record = {"network_address": address, "tower_id": binding["wTowerId"], "ip_address": None}
                bindings.append(record)
                try:
                    normalized = str(ip_address(address))
                except ValueError as e:
                    context.log.debug(f"Non-IP binding {address}: {e}")
                    continue
                record["ip_address"] = normalized
                if (not self.pivot or normalized != target_address) and normalized not in addresses:
                    addresses.append(normalized)
                    context.log.highlight(f"Address: {normalized}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        finally:
            if portmap is not None:
                try:
                    portmap.disconnect()
                except Exception as e:
                    errors.append(f"Closing OXID RPC connection: {e}")
        for error in errors:
            context.log.fail(error)
        return ActionResult(
            connection.args.protocol, self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if addresses else ResultStatus.NEGATIVE,
            self.ResultData(addresses, bindings, self.pivot), error="; ".join(errors) or None,
        )
