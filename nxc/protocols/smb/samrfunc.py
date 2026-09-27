# Majorly stolen from https://gist.github.com/ropnop/7a41da7aabb8455d0898db362335e139
# Which in turn stole from Impacket :)
# Code refactored and added to by @mjhallenbeck (Marshall-Hallenbeck on GitHub)

from impacket.dcerpc.v5 import lsat, lsad, samr
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SessionError
from nxc.helpers.rpc import NXCRPCConnection


class SamrFunc:
    def __init__(self, connection):
        self.logger = connection.logger
        self.connection = connection

        self.errors = []
        self.samr_query = None
        self.lsa_query = None
        try:
            self.samr_query = SAMRQuery(connection=connection, logger=self.logger)
            self.lsa_query = LSAQuery(connection=connection, logger=self.logger)
        except Exception as e:
            self.close()
            raise e

    def close(self):
        errors = []
        for query in (self.samr_query, self.lsa_query):
            if query is not None and query.dce is not None:
                try:
                    query.dce.disconnect()
                except Exception as e:
                    errors.append(str(e) or type(e).__name__)
                    self.logger.fail(f"Error closing local group RPC: {e}")
                finally:
                    query.dce = None
        return errors

    def get_builtin_groups(self, group):
        domains = self.samr_query.get_domains()
        members = {}
        if "Builtin" not in domains:
            self.logger.error("No Builtin group to query locally on")
            return {}, {}

        domain_handle = self.samr_query.get_domain_handle("Builtin")
        builtin_groups = self.samr_query.get_domain_aliases(domain_handle, group)
        if group:
            members = self.get_local_users(builtin_groups, domain_handle)
        return builtin_groups, members

    def get_custom_groups(self, group=None):
        domains = self.samr_query.get_domains()
        custom_groups = {}
        members = {}
        for domain in domains:
            if domain == "Builtin":
                continue
            domain_handle = self.samr_query.get_domain_handle(domain)
            domain_groups = self.samr_query.get_domain_aliases(domain_handle, group)
            custom_groups.update(domain_groups)
            if group:
                members.update(self.get_local_users(domain_groups, domain_handle))
        return custom_groups, members

    def get_local_groups(self, group=None):
        if group:
            self.logger.display(f"Querying group: {group}")
        groups, members = {}, {}
        for lookup in (self.get_builtin_groups, self.get_custom_groups):
            try:
                found_groups, found_members = lookup(group)
                groups.update(found_groups)
                members.update(found_members)
            except Exception as e:
                self.errors.append(str(e) or type(e).__name__)
                self.logger.fail(f"Error enumerating local groups: {e}")
        return groups, members

    def get_local_users(self, group, domain_handle):
        users = {}
        try:
            for alias_id in group.values():
                member_sids = self.samr_query.get_alias_members(domain_handle, alias_id)
                member_names = self.lsa_query.lookup_sids(member_sids)
                users.update(zip(member_sids, member_names, strict=True))
        except Exception as e:
            self.errors.append(str(e) or type(e).__name__)
            self.logger.debug(f"Error enumerating users in {group}: {e}")
        return users


class SAMRQuery:
    def __init__(self, connection=None, logger=None):
        self.connection = connection
        self.logger = logger
        self.dce = self.get_dce()
        try:
            self.server_handle = self.get_server_handle()
        except Exception as e:
            if self.dce is not None:
                self.dce.disconnect()
            raise e

    def get_dce(self):
        try:
            return NXCRPCConnection(self.connection).connect(r"\samr", samr.MSRPC_UUID_SAMR)
        except NetBIOSError as e:
            self.logger.error(f"NetBIOSError on Connection: {e}")
            return None
        except SessionError as e:
            self.logger.error(f"SessionError on Connection: {e}")
            return None

    def get_server_handle(self):
        if self.dce:
            try:
                resp = samr.hSamrConnect(self.dce)
            except samr.DCERPCException as e:
                if "rpc_s_access_denied" in str(e):
                    raise
                self.logger.debug(f"Error while connecting with Samr: {e}")
                return None
            return resp["ServerHandle"]
        else:
            self.logger.debug("Error creating Samr handle")

    def get_domains(self):
        """Calls the hSamrEnumerateDomainsInSamServer() method directly with list comprehension and extracts the "Name" value from each element in the "Buffer" list."""
        domains = samr.hSamrEnumerateDomainsInSamServer(self.dce, self.server_handle)["Buffer"]["Buffer"]
        return [domain["Name"] for domain in domains]

    def get_domain_handle(self, domain_name):
        resp = samr.hSamrLookupDomainInSamServer(self.dce, self.server_handle, domain_name)
        resp = samr.hSamrOpenDomain(self.dce, serverHandle=self.server_handle, domainId=resp["DomainId"])
        return resp["DomainHandle"]

    def get_domain_aliases(self, domain_handle, group=None):
        """Use a dictionary comprehension to generate the aliases dictionary.

        Calls the hSamrEnumerateAliasesInDomain() method directly in the dictionary comprehension and extracts the "Name" and "RelativeId" values from each element in the "Buffer" list
        """
        aliases = {alias["Name"]: alias["RelativeId"] for alias in samr.hSamrEnumerateAliasesInDomain(self.dce, domain_handle)["Buffer"]["Buffer"]}
        if group:
            aliases = {name: rid for name, rid in aliases.items() if name == group}
        return aliases

    def get_alias_handle(self, domain_handle, alias_id):
        resp = samr.hSamrOpenAlias(self.dce, domain_handle, desiredAccess=MAXIMUM_ALLOWED, aliasId=alias_id)
        return resp["AliasHandle"]

    def get_alias_members(self, domain_handle, alias_id):
        """Calls the hSamrGetMembersInAlias() method directly with list comprehension and extracts the "SidPointer" value from each element in the "Sids" list."""
        alias_handle = self.get_alias_handle(domain_handle, alias_id)
        return [member["SidPointer"].formatCanonical() for member in samr.hSamrGetMembersInAlias(self.dce, alias_handle)["Members"]["Sids"]]


class LSAQuery:
    def __init__(self, connection=None, logger=None):
        self.connection = connection
        self.logger = logger
        self.dce = self.get_dce()
        try:
            self.policy_handle = self.get_policy_handle()
        except Exception as e:
            if self.dce is not None:
                self.dce.disconnect()
            raise e

    def get_dce(self):
        try:
            return NXCRPCConnection(self.connection).connect(r"\lsarpc", lsat.MSRPC_UUID_LSAT)
        except NetBIOSError as e:
            self.logger.fail(f"NetBIOSError on Connection: {e}")
            return None

    def get_policy_handle(self):
        resp = lsad.hLsarOpenPolicy2(self.dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        return resp["PolicyHandle"]

    def lookup_sids(self, sids):
        """Use a list comprehension to generate the names list.

        It calls the hLsarLookupSids() method directly in the list comprehension and extracts the "Name" value from each element in the "Names" list.
        """
        return [translated_names["Name"] for translated_names in lsat.hLsarLookupSids(self.dce, self.policy_handle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)["TranslatedNames"]["Names"]]
