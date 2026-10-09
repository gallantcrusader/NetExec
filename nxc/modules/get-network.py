# Credit to @snovvcrash, @dirkjanm, @_dirkjan and @mpgn_x64
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ldap3.utils.dn import escape_rdn
from nxc.helpers.dns_records import DNS_RECORD, DNS_RPC_RECORD_A, DNS_RPC_RECORD_AAAA, DNS_RPC_RECORD_NODE_NAME
from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus


class NXCModule:
    name = "get-network"
    description = "Query all DNS records with the corresponding IP from the domain."
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    record_types = {0: "ZERO", 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}

    @dataclass
    class ResultData:
        zone: str
        search_base: str
        nodes: list[dict]
        records: list[dict]
        export_lines: list[str]

    result_type = ResultData

    def options(self, context, module_options):
        """
        ALL           Get DNS and IP (default: false)
        ONLY_HOSTS    Get DNS only (no ip) (default: false)
        """
        self.showall = str(module_options.get("ALL", False)).lower() in ("true", "1")
        self.showhosts = str(module_options.get("ONLY_HOSTS", False)).lower() in ("true", "1")

    def on_login(self, context, connection):
        zone = ".".join(re.findall(r"(?:^|,)DC=([^,]+)", connection.baseDN, flags=re.IGNORECASE))
        search_base = f"DC={escape_rdn(zone)},CN=MicrosoftDNS,DC=DomainDnsZones,{connection.baseDN}"
        context.log.display("Querying zone for records")
        nodes = parse_result_attributes(connection.search(
            searchFilter="(DC=*)", attributes=["dnsRecord", "dNSTombstoned", "name", "distinguishedName"], baseDN=search_base,
        ))
        errors = [connection.last_search_error] if connection.last_search_error else []
        records, export_lines, artifacts = [], [], []
        seen_ips = set()
        for node in nodes:
            name = node["name"]
            fqdn = zone if name == "@" else f"{name}.{zone}"
            values = node.get("dnsRecord", [])
            tombstoned = str(node.get("dNSTombstoned", "false")).lower() == "true"
            for raw in values if isinstance(values, list) else [values]:
                dr = DNS_RECORD(raw)
                value = None
                if dr["Type"] == 1:
                    value = DNS_RPC_RECORD_A(dr["Data"]).formatCanonical()
                elif dr["Type"] == 28:
                    value = DNS_RPC_RECORD_AAAA(dr["Data"]).formatCanonical()
                elif dr["Type"] in (2, 5, 12):
                    value = DNS_RPC_RECORD_NODE_NAME(dr["Data"])["nameNode"].toFqdn()
                records.append({
                    "name": name, "fqdn": fqdn, "type": self.record_types.get(dr["Type"]), "type_id": dr["Type"],
                    "value": value, "ttl": dr["TtlSeconds"], "serial": dr["Serial"], "timestamp": dr["TimeStamp"],
                    "rank": dr["Rank"], "flags": dr["Flags"], "tombstoned": tombstoned, "raw": raw,
                })
                if tombstoned or name in ("DomainDnsZones", "ForestDnsZones") or value is None:
                    continue
                if dr["Type"] not in (1, 28) and not (self.showall or self.showhosts):
                    continue
                if self.showhosts:
                    export_lines.append(fqdn)
                elif self.showall:
                    export_lines.append(f"{fqdn} \t {value}")
                elif value not in seen_ips:
                    seen_ips.add(value)
                    export_lines.append(value)

        context.log.highlight(f"Found {len(records)} records")
        path = Path(NXC_PATH) / "logs" / sanitize_path_component(f"{connection.host}_network_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.log")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(export_lines) + ("\n" if export_lines else ""), encoding="utf-8")
            artifacts.append(Artifact(path, "dns_inventory"))
            context.log.success(f"Dumped {len(export_lines)} lines to {path}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        for error in errors:
            context.log.fail(error)
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if records else ResultStatus.NEGATIVE,
            self.ResultData(zone, search_base, nodes, records, export_lines), artifacts=artifacts, error="; ".join(errors) or None,
        )
