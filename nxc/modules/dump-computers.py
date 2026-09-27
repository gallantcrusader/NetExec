from dataclasses import dataclass
from pathlib import Path

from nxc.playbooks.results import ActionResult, Artifact, ResultStatus
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    name = "dump-computers"
    description = "Dumps FQDN and OS of all computers in the domain"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        computers: list[dict]
        output_lines: list[str]

    result_type = ResultData

    def options(self, context, module_options):
        """
        TYPE        Only dump NETBIOS or FQDN instead of 'FQDN (OS Version)'
        OUTPUT      Output to file in addition to printing to console

        Examples
        --------
        netexec ldap $DC-IP -u $username -p $password -M dump-computers
        netexec ldap $DC-IP -u $username -p $password -M dump-computers -o TYPE=netbios
        netexec ldap $DC-IP -u $username -p $password -M dump-computers -o TYPE=fqdn
        netexec ldap $DC-IP -u $username -p $password -M dump-computers -o TYPE=netbios OUTPUT=<location>
        """
        self.output_file = None
        self.netbios_only = False
        self.fqdn_only = False

        if "OUTPUT" in module_options:
            self.output_file = module_options["OUTPUT"]
        if "TYPE" in module_options:
            if module_options["TYPE"].lower() == "netbios":
                self.netbios_only = True
            elif module_options["TYPE"].lower() == "fqdn":
                self.fqdn_only = True

    def on_login(self, context, connection):
        resp = connection.search(
            searchFilter="(objectCategory=computer)",
            attributes=["dNSHostName", "operatingSystem"]
        )
        resp_parsed = parse_result_attributes(resp)

        answers = []
        computers = []
        errors = [connection.last_search_error] if connection.last_search_error else []
        artifacts = []
        context.log.debug(f"Total number of records returned: {len(resp_parsed)}")

        for item in resp_parsed:
            dns_host_name = item.get("dNSHostName")
            operating_system = item.get("operatingSystem", "Unknown OS")
            if not dns_host_name:
                context.log.debug(f"Skipping computer without dNSHostName: {item.get('cn', '<unknown>')}")
                continue

            if self.netbios_only:
                netbios_name = dns_host_name.split(".")[0]
                answer = netbios_name
            elif self.fqdn_only:
                answer = dns_host_name
            else:
                answer = f"{dns_host_name} ({operating_system})"
            answers.append(answer)
            computers.append({"dns_hostname": dns_host_name, "operating_system": item.get("operatingSystem"), "dns_short_name": dns_host_name.split(".")[0]})

        context.log.success("Found the following computers:")
        for answer in answers:
            context.log.highlight(answer)

        if self.output_file:
            try:
                with open(self.output_file, "w") as f:
                    f.write("\n".join(answers) + "\n")
                artifacts.append(Artifact(Path(self.output_file), "computer_list"))
                context.log.success(f"Results saved to {self.output_file}")
            except Exception as e:
                errors.append(str(e) or type(e).__name__)
                context.log.fail(f"Failed to write to file {self.output_file}: {e}")
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if computers else ResultStatus.NEGATIVE,
            self.ResultData(computers, answers), artifacts=artifacts, error="; ".join(errors) or None,
        )
