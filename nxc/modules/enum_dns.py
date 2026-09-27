from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_filename
from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus


class NXCModule:
    """Uses WMI to dump DNS from an AD DNS Server. Module by @fang0654."""

    name = "enum_dns"
    description = "Uses WMI to dump DNS from an AD DNS Server"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        zones: list[str]
        records: list[dict]
        queried_zones: list[str]

    result_type = ResultData

    def __init__(self, context=None, module_options=None):
        self.domains = None

    def options(self, context, module_options):
        """DOMAIN  Domain to enumerate DNS for. Defaults to all zones."""
        self.domains = module_options.get("DOMAIN") if module_options else None

    def on_admin_login(self, context, connection):
        errors, records, queried_zones, artifacts, lines = [], [], [], [], []
        if self.domains:
            domains = [self.domains]
        else:
            output = connection.wmi_query("Select Name FROM MicrosoftDNS_Zone", "root\\microsoftdns") or []
            domains = list(dict.fromkeys(result["Name"]["value"] for result in output))
            if connection.last_wmi_error:
                errors.append(connection.last_wmi_error)
            context.log.success(f"Domains retrieved: {domains}")

        # A partial zone listing is retained without starting additional queries.
        for domain in domains if not errors else []:
            literal = domain.replace("\\", "\\\\").replace("'", "\\'")
            output = connection.wmi_query(
                f"Select * FROM MicrosoftDNS_ResourceRecord WHERE DomainName = '{literal}'",
                "root\\microsoftdns",
            ) or []
            queried_zones.append(domain)
            if connection.last_wmi_error:
                errors.append(f"{domain}: {connection.last_wmi_error}")
            if output:
                context.log.highlight(f"Results for {domain}")
                lines.append(f"Results for {domain}")
            for entry in output:
                text = entry.get("TextRepresentation", {}).get("value")
                records.append({"zone": domain, "text": text, "properties": entry})
                if text is not None:
                    context.log.highlight(text)
                    lines.append(text)
            if errors:
                break

        path = Path(NXC_PATH) / "logs" / f"DNS-Enum-{sanitize_filename(connection.host)}-{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.log"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            artifacts.append(Artifact(path, "dns_records"))
            context.log.display(f"Saved raw output to {path}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        for error in errors:
            context.log.fail(error)
        return ActionResult(
            connection.args.protocol, self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if records else ResultStatus.NEGATIVE,
            self.ResultData(domains, records, queried_zones), artifacts=artifacts, error="; ".join(errors) or None,
        )
