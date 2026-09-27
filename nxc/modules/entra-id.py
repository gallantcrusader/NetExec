import re
from dataclasses import dataclass

from ldap3.utils.conv import escape_filter_chars
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Module by @NeffIsBack"""

    name = "entra-id"
    description = "Find the Entra ID sync server"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        msol_accounts: list[dict]
        adsync_accounts: list[dict]
        candidates: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        """No options available."""

    def on_login(self, context, connection):
        errors = []
        msol = self.search(connection, "(sAMAccountName=MSOL_*)", ["sAMAccountName", "cn", "description"], errors)
        adsync = self.search(connection, "(sAMAccountName=ADSyncMSA*)", ["sAMAccountName", "cn", "msDS-HostServiceAccountBL"], errors) if not errors else []
        candidates = []
        for account in msol if not errors else []:
            descriptions = account.get("description", [])
            for description in descriptions if isinstance(descriptions, list) else [descriptions]:
                match = re.search(r"computer (?P<host>.*?) configured", description)
                if not match:
                    continue
                hostname = match.group("host")
                computers = self.search(connection, f"(sAMAccountName={escape_filter_chars(hostname + '$')})", ["dNSHostName", "cn", "distinguishedName"], errors)
                candidate = {"source": "msol_description", "account": account.get("sAMAccountName"), "evidence": description,
                             "hostname": hostname, "computers": computers, "address": None, "resolution_error": None}
                candidates.append(candidate)
                if not errors:
                    self.resolve(connection, candidate, computers[0].get("dNSHostName", hostname) if computers else hostname, errors)
                if errors:
                    break
            if errors:
                break
        for account in adsync if not errors else []:
            backlinks = account.get("msDS-HostServiceAccountBL", [])
            for dn in backlinks if isinstance(backlinks, list) else [backlinks]:
                computers = self.search(connection, f"(distinguishedName={escape_filter_chars(dn)})", ["dNSHostName", "cn", "sAMAccountName", "distinguishedName"], errors)
                candidate = {"source": "adsync_backlink", "account": account.get("sAMAccountName"), "evidence": dn,
                             "hostname": computers[0].get("cn") if computers else None, "computers": computers, "address": None, "resolution_error": None}
                candidates.append(candidate)
                if computers and not errors:
                    self.resolve(connection, candidate, computers[0].get("dNSHostName") or candidate["hostname"], errors)
                if errors:
                    break
            if errors:
                break
        for candidate in candidates:
            context.log.highlight(f"Candidate {candidate['hostname'] or candidate['evidence']} from {candidate['account']} ({candidate['source']}): {candidate['address']}")
        for error in errors:
            context.log.fail(error)
        return ActionResult("ldap", self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if candidates else ResultStatus.NEGATIVE,
                            self.ResultData(msol, adsync, candidates), error="; ".join(errors) or None)

    def search(self, connection, query, attributes, errors):
        records = parse_result_attributes(connection.search(query, attributes))
        if connection.last_search_error:
            errors.append(connection.last_search_error)
        return records

    def resolve(self, connection, candidate, hostname, errors):
        if not hostname:
            return
        try:
            candidate["address"] = connection.resolver(hostname)
            if not candidate["address"] or not candidate["address"].get("host"):
                raise RuntimeError(f"No address returned for {hostname}")
        except Exception as e:
            candidate["resolution_error"] = str(e) or type(e).__name__
            errors.append(candidate["resolution_error"])
