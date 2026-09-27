#!/usr/bin/env python3

from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH
from nxc.helpers.path import sanitize_filename
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus


class NXCModule:
    """
    Extract obsolete operating systems from LDAP
    Module by Brandon Fisher @shad0wcntr0ller
    """
    name = "obsolete"
    description = "Extract all obsolete operating systems from LDAP"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        computers: list[dict]
        search_filter: str

    result_type = ResultData

    def ldap_time_to_datetime(self, ldap_time):
        """Convert an LDAP timestamp to a datetime object."""
        if ldap_time is None:
            return None
        if str(ldap_time) == "0":  # Account for never-set passwords
            return "Never"
        try:
            epoch = datetime(1601, 1, 1) + timedelta(seconds=int(ldap_time) / 10000000)
            return epoch.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Conversion Error"

    def options(self, context, module_options):
        """No module-specific options required."""

    def on_login(self, context, connection):
        search_filter = ("(&(objectclass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                         "(|(operatingSystem=*Windows 6*)(operatingSystem=*Windows 2000*)"
                         "(operatingSystem=*Windows XP*)(operatingSystem=*Windows Vista*)"
                         "(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)"
                         "(operatingSystem=*Windows 8.1*)(operatingSystem=*Windows Server 2003*)"
                         "(operatingSystem=*Windows Server 2008*)(operatingSystem=*Windows Server 2012*)))")
        attributes = ["name", "operatingSystem", "dNSHostName", "pwdLastSet"]

        context.log.debug(f"Search Filter={search_filter}")
        response = connection.search(searchFilter=search_filter, attributes=attributes)
        errors = [connection.last_search_error] if connection.last_search_error else []
        computers = []
        artifacts = []
        for item in parse_result_attributes(response):
            hostname = item.get("dNSHostName")
            if not hostname or not item.get("operatingSystem"):
                continue
            resolved = connection.resolver(hostname)
            address = resolved.get("host") if resolved else None
            computer = {**item, "address": address, "pwdLastSet_readable": self.ldap_time_to_datetime(item.get("pwdLastSet")), "resolution_error": None}
            if address is None:
                computer["resolution_error"] = f"No address resolved for {hostname}"
                errors.append(computer["resolution_error"])
            computers.append(computer)
        if computers:
            filename = Path(NXC_PATH) / "logs" / f"{sanitize_filename(connection.domain)}-{sanitize_filename(connection.host)}-{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.obsoletehosts.txt"
            try:
                filename.parent.mkdir(parents=True, exist_ok=True)
                with filename.open("w") as output:
                    for computer in computers:
                        line = f"{computer['dNSHostName']} ({computer['address'] or 'N/A'}) : {computer['operatingSystem']} [pwd-last-set: {computer['pwdLastSet_readable'] or 'Unknown'}]"
                        context.log.highlight(line)
                        output.write(line + "\n")
                artifacts.append(Artifact(filename, "obsolete_hosts"))
                context.log.display(f"Saved {len(computers)} matching hosts to {filename}")
            except Exception as e:
                errors.append(str(e) or type(e).__name__)
        else:
            context.log.display("No Obsolete Hosts Identified")
        for error in errors:
            context.log.fail(error)
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if computers else ResultStatus.NEGATIVE,
            self.ResultData(computers, search_filter), artifacts=artifacts, error="; ".join(errors) or None,
        )
