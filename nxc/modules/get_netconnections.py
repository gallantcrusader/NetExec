from datetime import datetime
from dataclasses import dataclass
from pathlib import Path

from nxc.playbooks.results import ActionResult, Artifact, ResultStatus, json_value
from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH
import json


class NXCModule:
    """
    Uses WMI to extract network connections, used to find multi-homed hosts.
    Module by @fang0654

    """

    name = "get_netconnections"
    description = "Uses WMI to query network connections."
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        adapters: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        cards = connection.wmi_query("select DNSDomainSuffixSearchOrder, IPAddress from win32_networkadapterconfiguration") or []
        errors = [connection.last_wmi_error] if connection.last_wmi_error else []
        artifacts = []
        for card in cards:
            addresses = card.get("IPAddress", {}).get("value")
            if addresses:
                context.log.success(f"IP Address: {addresses}\tSearch Domain: {card.get('DNSDomainSuffixSearchOrder', {}).get('value')}")
        path = Path(NXC_PATH) / "logs" / sanitize_path_component(f"network-connections-{connection.host}-{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.log")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(json_value([cards] if cards else [])), encoding="utf-8")
            artifacts.append(Artifact(path, "network_connections"))
            context.log.display(f"Saved raw output to {path}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
            context.log.fail(f"Failed to save network connections: {e}")
        return ActionResult(
            connection.args.protocol, self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if cards else ResultStatus.NEGATIVE,
            self.ResultData(cards), artifacts=artifacts, error="; ".join(errors) or None,
        )
