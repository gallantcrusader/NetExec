from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Enumerate SQL Server logins (SQL, Domain, Local users)
    Module by deathflamingo, modified by mpgn
    """

    name = "enum_logins"
    description = "Enumerate SQL Server logins (SQL, Domain, Local users)"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        default_domain: str | None
        logins: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        errors = []
        domain = None
        logins = []
        try:
            rows = connection.conn.sql_query("SELECT DEFAULT_DOMAIN() as domain_name;")
            if connection.conn.lastError:
                errors.append(str(connection.conn.lastError))
            elif rows:
                domain = rows[0].get("domain_name")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        try:
            rows = connection.conn.sql_query("""
                SELECT name, type, type_desc, is_disabled, create_date
                FROM sys.server_principals
                WHERE type IN ('S', 'U', 'G', 'C', 'K') AND name NOT LIKE '##%'
                ORDER BY type_desc, name;
            """) or []
            if connection.conn.lastError:
                errors.append(str(connection.conn.lastError))
            for row in rows:
                login = dict(row)
                login["login_type"] = self.login_type(row, domain)
                logins.append(login)
                status = "UNKNOWN" if row.get("is_disabled") is None else "DISABLED" if row["is_disabled"] else "ENABLED"
                context.log.highlight(f"{row['name']:<35} {login['login_type']:<15} {status}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        for error in errors:
            context.log.fail(error)
        if not logins and not errors:
            context.log.display("No logins found.")
        return ActionResult(
            "mssql", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if logins else ResultStatus.NEGATIVE,
            self.ResultData(domain, logins), error="; ".join(errors) or None,
        )

    def login_type(self, row, domain):
        types = {"SQL_LOGIN": "SQL User", "WINDOWS_GROUP": "Windows Group", "CERTIFICATE_MAPPED_LOGIN": "Certificate Login", "ASYMMETRIC_KEY_MAPPED_LOGIN": "Asymmetric Key Login"}
        if row.get("type_desc") == "WINDOWS_LOGIN":
            if domain and row["name"].casefold().startswith(domain.casefold() + "\\"):
                return "Domain User"
            # A non-default prefix may be a local machine or another domain.
            return "Windows User"
        return types.get(row.get("type_desc"), row.get("type_desc") or "Unknown")
