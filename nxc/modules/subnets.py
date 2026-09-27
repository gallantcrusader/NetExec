from dataclasses import dataclass
from sys import exit

from ldap3.utils.conv import escape_filter_chars
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Retrieves the different Sites and Subnets of an Active Directory

    Authors:
      Podalirius: @podalirius_
    """
    name = "subnets"
    description = "Retrieves the different Sites and Subnets of an Active Directory"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        sites: list[dict]
        servers_queried: bool

    result_type = ResultData

    def options(self, context, module_options):
        """SHOWSERVERS    Toggle printing of servers (default: true)"""
        self.showservers = True
        if module_options and "SHOWSERVERS" in module_options:
            if module_options["SHOWSERVERS"].lower() in {"true", "1"}:
                self.showservers = True
            elif module_options["SHOWSERVERS"].lower() in {"false", "0"}:
                self.showservers = False
            else:
                context.log.fail("Could not parse showservers option for 'SHOWSERVERS'. Please use 'true' or 'false'.")
                exit(1)

    def on_login(self, context, connection):
        dn = connection.args.base_dn or connection.ldap_connection._baseDN
        context.log.display("Getting the Sites and Subnets from domain")
        sites = parse_result_attributes(connection.search(
            "(objectClass=site)", ["distinguishedName", "name", "description"], baseDN=f"CN=Configuration,{dn}",
        ))
        errors = [connection.last_search_error] if connection.last_search_error else []
        records = []
        for site in sites:
            site_dn = site["distinguishedName"]
            subnets = parse_result_attributes(connection.search(
                f"(siteObject={escape_filter_chars(site_dn)})", ["distinguishedName", "name"], baseDN=f"CN=Sites,CN=Configuration,{dn}",
            ))
            if connection.last_search_error:
                errors.append(connection.last_search_error)
            servers = []
            if self.showservers:
                servers = parse_result_attributes(connection.search("(objectClass=server)", ["cn"], baseDN=site_dn))
                if connection.last_search_error:
                    errors.append(connection.last_search_error)
            records.append({
                "name": site["name"], "distinguished_name": site_dn, "description": site.get("description", ""),
                "subnets": subnets, "servers": [server["cn"] for server in servers],
            })
            for subnet in subnets or [None]:
                for server in servers or [None]:
                    message = f'Site "{site["name"]}"'
                    if subnet:
                        message += f' (Subnet:{subnet["name"]})'
                    if site.get("description"):
                        message += f' (description:"{site["description"]}")'
                    if server:
                        message += f' (Server:{server["cn"]})'
                    context.log.highlight(message)
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if records else ResultStatus.NEGATIVE,
            self.ResultData(records, self.showservers), error="; ".join(errors) if errors else None,
        )
