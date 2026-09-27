from dataclasses import dataclass
from sys import exit

from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Module by CyberCelt: @Cyb3rC3lt

    Initial module:
      https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    """

    name = "find-computer"
    description = "Finds computers in the domain via the provided text"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        text: str
        computers: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        """
        TEXT    Search TEXT in the operating system or name of the computer.

        Examples:
        nxc ldap $DC-IP -u Username -p Password -M find-computer -o TEXT="server"
        nxc ldap $DC-IP -u Username -p Password -M find-computer -o TEXT="SQL"
        """
        self.TEXT = ""

        if "TEXT" in module_options:
            self.TEXT = module_options["TEXT"]
        else:
            context.log.error("TEXT option is required!")
            exit(1)

    def on_login(self, context, connection):
        text = escape_filter_chars(self.TEXT)
        search_filter = f"(&(objectCategory=computer)(|(operatingSystem=*{text}*)(name=*{text}*)))"
        context.log.debug(f"Search Filter={search_filter}")
        response = connection.search(searchFilter=search_filter, attributes=["dNSHostName", "operatingSystem"])
        errors = [connection.last_search_error] if connection.last_search_error else []
        computers = []
        for item in parse_result_attributes(response):
            hostname = item.get("dNSHostName")
            if not hostname:
                continue
            resolution = connection.resolver(hostname)
            address = resolution.get("host") if resolution else None
            computer = {"dns_hostname": hostname, "operating_system": item.get("operatingSystem"), "address": address, "resolution_error": None}
            if address is None:
                computer["resolution_error"] = f"No address resolved for {hostname}"
                errors.append(computer["resolution_error"])
            computers.append(computer)
            context.log.highlight(f"{hostname} ({item.get('operatingSystem', 'Unknown OS')}) ({address or 'No IP Found'})")
        if not computers:
            context.log.success(f"Unable to find any computers with the text {self.TEXT}")
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if computers else ResultStatus.NEGATIVE,
            self.ResultData(self.TEXT, computers), error="; ".join(errors) or None,
        )
