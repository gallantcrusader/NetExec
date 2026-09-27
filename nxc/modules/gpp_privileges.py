from dataclasses import dataclass

from ldap3.utils.conv import escape_filter_chars
from nxc.playbooks.results import ActionResult, ResultStatus
from io import BytesIO
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Module to retrieve privileges assigned via Group Policy Objects (GPOs) by parsing GptTmpl.inf files
    and resolving SIDs using LDAP.
    """

    name = "gpp_privileges"
    description = "Extracts privileges assigned via GPOs and resolves SIDs via LDAP."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    WELL_KNOWN_SIDS = {
        "S-1-0": "Null Authority",
        "S-1-0-0": "Nobody",
        "S-1-1": "World Authority",
        "S-1-1-0": "Everyone",
        "S-1-2": "Local Authority",
        "S-1-2-0": "Local",
        "S-1-2-1": "Console Logon",
        "S-1-3": "Creator Authority",
        "S-1-3-0": "Creator Owner",
        "S-1-3-1": "Creator Group",
        "S-1-3-2": "Creator Owner Server",
        "S-1-3-3": "Creator Group Server",
        "S-1-3-4": "Owner Rights",
        "S-1-5-80-0": "All Services",
        "S-1-4": "Non-unique Authority",
        "S-1-5": "NT Authority",
        "S-1-5-1": "Dialup",
        "S-1-5-2": "Network",
        "S-1-5-3": "Batch",
        "S-1-5-4": "Interactive",
        "S-1-5-6": "Service",
        "S-1-5-7": "Anonymous",
        "S-1-5-8": "Proxy",
        "S-1-5-9": "Enterprise Domain Controllers",
        "S-1-5-10": "Principal Self",
        "S-1-5-11": "Authenticated Users",
        "S-1-5-12": "Restricted Code",
        "S-1-5-13": "Terminal Server Users",
        "S-1-5-14": "Remote Interactive Logon",
        "S-1-5-15": "This Organization",
        "S-1-5-17": "This Organization",
        "S-1-5-18": "Local System",
        "S-1-5-19": "NT Authority",
        "S-1-5-20": "NT Authority",
        "S-1-5-32-544": "Administrators",
        "S-1-5-32-545": "Users",
        "S-1-5-32-546": "Guests",
        "S-1-5-32-547": "Power Users",
        "S-1-5-32-548": "Account Operators",
        "S-1-5-32-549": "Server Operators",
        "S-1-5-32-550": "Print Operators",
        "S-1-5-32-551": "Backup Operators",
        "S-1-5-32-552": "Replicators",
        "S-1-5-64-10": "NTLM Authentication",
        "S-1-5-64-14": "SChannel Authentication",
        "S-1-5-64-21": "Digest Authority",
        "S-1-5-80": "NT Service",
        "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
        "S-1-16-0": "Untrusted Mandatory Level",
        "S-1-16-4096": "Low Mandatory Level",
        "S-1-16-8192": "Medium Mandatory Level",
        "S-1-16-8448": "Medium Plus Mandatory Level",
        "S-1-16-12288": "High Mandatory Level",
        "S-1-16-16384": "System Mandatory Level",
        "S-1-16-20480": "Protected Process Mandatory Level",
        "S-1-16-28672": "Secure Process Mandatory Level",
        "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
        "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
        "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
        "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
        "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
        "S-1-5-32-559": "BUILTIN\\Performance Log Users",
        "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
        "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
        "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
        "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
        "S-1-5-32-573": "BUILTIN\\Event Log Readers",
        "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
        "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
        "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
        "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
        "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
        "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
        "S-1-5-32-580": "BUILTIN\\Remote Management Users",
    }

    @dataclass
    class ResultData:
        policies: list[dict]
        ldap_resolution_requested: bool

    result_type = ResultData

    def options(self, context, module_options):
        """NO_LDAP      If set to True, disables LDAP queries for resolving SIDs."""
        self.no_ldap = str(module_options.get("NO_LDAP", "false")).lower() in ("true", "1")

    def on_login(self, context, connection):
        self.context = context
        self.errors = []
        policies = []
        paths = []
        try:
            connection.conn.listPath("SYSVOL", "*")
            paths = connection.spider("SYSVOL", pattern=["GptTmpl.inf"])
        except Exception as e:
            self.errors.append(str(e) or type(e).__name__)
        for path in paths:
            policy = {"path": path, "privileges": [], "error": None}
            policies.append(policy)
            try:
                with BytesIO() as buffer:
                    connection.conn.getFile("SYSVOL", path, buffer.write)
                    content = buffer.getvalue().decode("utf-16le").lstrip("\ufeff")
                policy["privileges"] = [{"privilege": privilege, "principals": [{"sid": sid, "name": None} for sid in sids]} for privilege, sids in self.extract_privileges(content).items()]
            except Exception as e:
                policy["error"] = str(e) or type(e).__name__
                self.errors.append(f"{path}: {policy['error']}")
        ldap_connection = None
        base_dn = None
        self.ldap_session = None
        unresolved = any(principal["sid"] not in self.WELL_KNOWN_SIDS for policy in policies for privilege in policy["privileges"] for principal in privilege["principals"])
        try:
            if not self.no_ldap and unresolved:
                playbook = getattr(context, "playbook", None)
                if playbook is not None:
                    credential = getattr(context, "credential", None)
                    source = getattr(context, "session", None)
                    anonymous = source is not None and getattr(source.result.data, "anonymous", False)
                    if credential is None and not anonymous:
                        self.errors.append("LDAP SID resolution requires a stored credential reference or an anonymous source session")
                    else:
                        session = playbook.ldap(credential=credential, anonymous=anonymous, stop_on_error=False)
                        if session.ok:
                            self.ldap_session = session
                        else:
                            self.errors.append(session.result.error or "LDAP resolution session could not authenticate")
                else:
                    ldap_connection = self.initialize_ldap_connection(connection)
                    if ldap_connection:
                        base_dn = self.get_basedn(ldap_connection)
            for policy in policies:
                for privilege in policy["privileges"]:
                    for principal in privilege["principals"]:
                        principal["name"] = self.resolve_sid(principal["sid"], ldap_connection, base_dn)
                    context.log.highlight(f"{policy['path']} {privilege['privilege']}: {privilege['principals']}")
        finally:
            if ldap_connection:
                try:
                    ldap_connection.close()
                except Exception as e:
                    self.errors.append(f"Closing LDAP resolution connection: {e}")
        for error in self.errors:
            context.log.fail(error)
        found = any(policy["privileges"] for policy in policies)
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if self.errors else ResultStatus.SUCCESS if found else ResultStatus.NEGATIVE,
            self.ResultData(policies, not self.no_ldap), error="; ".join(self.errors) or None,
        )

    def get_basedn(self, ldap_connection):
        root = ldap_connection.search(
                        scope=ldapasn1_impacket.Scope("baseObject"),
                        attributes=["defaultNamingContext"],
                        sizeLimit=0,
                    )
        return parse_result_attributes(root)[0]["defaultNamingContext"]

    def extract_privileges(self, content):
        """Read only the Privilege Rights section, preserving empty assignments."""
        privileges = {}
        active = False
        for line in content.lstrip("\ufeff").splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                active = line.casefold() == "[privilege rights]"
                continue
            if active and "=" in line:
                privilege, values = line.split("=", 1)
                privileges[privilege.strip()] = [value.strip().lstrip("*") for value in values.split(",") if value.strip()]
        return privileges

    def initialize_ldap_connection(self, connection):
        """Initialize LDAP resolution using the SMB session credentials."""
        ldap_connection = None
        try:
            ldap_connection = ldap_impacket.LDAPConnection(url=f"ldap://{connection.remoteName}", dstIp=connection.host)
            if connection.kerberos:
                ldap_connection.kerberosLogin(
                    connection.username,
                    connection.password or "",
                    connection.domain,
                    connection.lmhash,
                    connection.nthash,
                    connection.aesKey or "",
                    kdcHost=connection.kdcHost,
                    useCache=bool(connection.use_kcache),
                )
            else:
                ldap_connection.login(
                    user=connection.username,
                    password=connection.password or "",
                    domain=connection.domain,
                    lmhash=connection.lmhash,
                    nthash=connection.nthash,
                )
            self.context.log.success("Connected to LDAP.")
        except Exception as e:
            self.errors.append(f"LDAP connection failed: {e}")
            if ldap_connection is not None:
                try:
                    ldap_connection.close()
                except Exception as e:
                    self.errors.append(f"Closing failed LDAP connection: {e}")
            return None
        return ldap_connection

    def resolve_sid(self, sid, ldap_connection, base_dn):
        if sid in self.WELL_KNOWN_SIDS:
            return self.WELL_KNOWN_SIDS[sid]
        if self.ldap_session is not None:
            result = self.ldap_session.query(query=[f"(objectSid={escape_filter_chars(sid)})", "sAMAccountName"], stop_on_error=False)
            if result.error:
                self.errors.append(f"Resolving {sid}: {result.error}")
            records = getattr(result.data, "entries", [])
            if records:
                return records[0].get("sAMAccountName")
        elif ldap_connection:
            response = ldap_connection.search(searchBase=base_dn, searchFilter=f"(objectSid={escape_filter_chars(sid)})", attributes=["sAMAccountName"])
            records = parse_result_attributes(response)
            if records:
                return records[0].get("sAMAccountName")
        return None
