import re
from dataclasses import dataclass

from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Find PKI enrollment services and templates. By @qtc_de and @snovvcrash."""

    name = "adcs"
    description = "Find PKI Enrollment Services in Active Directory and Certificate Templates Names"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        base_dn: str
        server: str | None
        services: list[dict]
        templates: list[str]

    result_type = ResultData

    def __init__(self, context=None, module_options=None):
        self.server = None
        self.base_dn = None

    def options(self, context, module_options):
        """
        SERVER             PKI Enrollment Server to enumerate templates for. Default is None, use CN name
        BASE_DN            The base domain name for the LDAP query
        """
        self.server = module_options.get("SERVER")
        self.base_dn = module_options.get("BASE_DN")

    def on_login(self, context, connection):
        base_dn = "CN=Configuration," + (self.base_dn if self.base_dn is not None else connection.baseDN)
        search_filter = "(objectClass=pKIEnrollmentService)"
        if self.server is not None:
            server_dn = f"CN={escape_rdn(self.server)},CN=Enrollment Services,CN=Public Key Services,CN=Services,{base_dn}"
            search_filter = f"(&(objectClass=pKIEnrollmentService)(distinguishedName={escape_filter_chars(server_dn)}))"
            context.log.highlight(f"Using PKI CN: {self.server}")
        context.log.display(f"Starting LDAP search with search filter '{search_filter}'")
        entries = parse_result_attributes(connection.search(
            search_filter,
            ["distinguishedName", "cn", "dNSHostName", "msPKI-Enrollment-Servers", "certificateTemplates"],
            baseDN=base_dn,
        ))
        services, templates = [], []
        for entry in entries:
            values = entry.get("msPKI-Enrollment-Servers", [])
            values = values if isinstance(values, list) else [values]
            urls = [match.group(0) for value in values for match in re.finditer(r"https?://[^\r\n]+", value)]
            names = entry.get("certificateTemplates", [])
            names = names if isinstance(names, list) else [names]
            services.append({"attributes": entry, "urls": urls, "templates": names})
            for name in names:
                if name not in templates:
                    templates.append(name)
            if self.server is None:
                if entry.get("dNSHostName"):
                    context.log.highlight(f"Found PKI Enrollment Server: {entry['dNSHostName']}")
                if entry.get("cn"):
                    context.log.highlight(f"Found CN: {entry['cn']}")
                for url in urls:
                    context.log.highlight(f"Found PKI Enrollment WebService: {url}")
            else:
                for name in names:
                    context.log.highlight(f"Found Certificate Template: {name}")
        error = connection.last_search_error
        if error:
            context.log.fail(error)
        elif not entries:
            context.log.display("No matching PKI enrollment services found.")
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if error else ResultStatus.SUCCESS if entries else ResultStatus.NEGATIVE,
            self.ResultData(base_dn, self.server, services, templates), error=error,
        )
