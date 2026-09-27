from dataclasses import dataclass
from sys import exit

from ldap3.utils.conv import escape_filter_chars
from nxc.playbooks.results import ActionResult, ResultStatus
from impacket.ldap.ldap import MODIFY_ADD, MODIFY_DELETE
from impacket.dcerpc.v5 import samr
from nxc.helpers.rpc import NXCRPCConnection
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module for adding/removing users to/from groups
    Module by @termanix
    """

    name = "modify-group"
    description = "Modify the group membership of users and computers"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    @dataclass
    class ResultData:
        user: str
        group: str
        remove: bool
        completed: bool = False
        user_dn: str | None = None
        group_dn: str | None = None
        user_rid: int | None = None
        group_rid: int | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """
        Required:
        GROUP       Name of the group to add/remove the user to/from
        USER        Username of the account to modify

        Optional:
        REMOVE      Set to 'True' to remove the user from the specified group instead of adding (default: False)

        Examples
        --------
        Adding a user to a group:
            netexec smb <DC_IP> -u adminuser -p password -M modify-group -o USER='targetuser' GROUP='Domain Admins'
            netexec ldap <DC_IP> -u adminuser -p password -M modify-group -o USER='targetuser' GROUP='Enterprise Admins'

        Removing a user from a group:
            netexec smb <DC_IP> -u adminuser -p password -M modify-group -o USER='targetuser' GROUP='Domain Admins' REMOVE=True
            netexec ldap <DC_IP> -u adminuser -p password -M modify-group -o USER='targetuser' GROUP='Enterprise Admins' REMOVE=True

        SMB/SAMR KNOWN LIMITATIONS:
            - SAMR only supports modification of Global security groups.
              Domain Local and Universal groups require the LDAP protocol.
            - Cross-domain groups (e.g. Enterprise Admins) cannot be modified via SAMR.
              Use LDAP instead.

        """
        self.group = module_options.get("GROUP")
        self.target_user = module_options.get("USER")
        self.remove = module_options.get("REMOVE", "False").lower() == "true"

        if not (self.target_user and self.group):
            context.log.fail("USER and GROUP parameters are required!")
            exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.data = self.ResultData(self.target_user, self.group, self.remove)
        self.errors = []
        if context.protocol == "smb":
            self.modify_group_smb()
        else:
            self.modify_group_ldap()
        for error in self.errors:
            context.log.fail(error)
        if self.data.completed:
            context.log.success(f"Membership {'removal' if self.remove else 'addition'} acknowledged for {self.target_user} in {self.group}")
        return ActionResult(
            context.protocol, self.name, connection.host,
            ResultStatus.FAILED if self.errors or not self.data.completed else ResultStatus.SUCCESS,
            self.data, error="; ".join(self.errors) or None,
        )

    def modify_group_smb(self):
        dce = None
        handles = []
        try:
            dce = NXCRPCConnection(self.connection).connect(r"\samr", samr.MSRPC_UUID_SAMR)
            server = samr.hSamrConnect(dce, self.connection.host + "\x00")["ServerHandle"]
            handles.append(server)
            sid = samr.hSamrLookupDomainInSamServer(dce, server, self.connection.domain)["DomainId"]
            domain = samr.hSamrOpenDomain(dce, server, domainId=sid)["DomainHandle"]
            handles.append(domain)
            user_rid = samr.hSamrLookupNamesInDomain(dce, domain, (self.target_user,))["RelativeIds"]["Element"][0]
            group_rid = samr.hSamrLookupNamesInDomain(dce, domain, (self.group,))["RelativeIds"]["Element"][0]
            user_rid = int(user_rid if isinstance(user_rid, int) else user_rid["Data"])
            group_rid = int(group_rid if isinstance(group_rid, int) else group_rid["Data"])
            self.data.user_rid = user_rid
            self.data.group_rid = group_rid
            group = samr.hSamrOpenGroup(dce, domain, groupId=group_rid)["GroupHandle"]
            handles.append(group)
            if self.remove:
                samr.hSamrRemoveMemberFromGroup(dce, group, user_rid)
            else:
                samr.hSamrAddMemberToGroup(dce, group, user_rid, 0x7)
            self.data.completed = True
        except Exception as e:
            self.errors.append(str(e) or type(e).__name__)
        finally:
            for handle in reversed(handles):
                try:
                    samr.hSamrCloseHandle(dce, handle)
                except Exception as e:
                    self.errors.append(f"Closing SAMR handle: {e}")
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception as e:
                    self.errors.append(f"Closing SAMR connection: {e}")

    def find_object_dn(self, value):
        response = self.connection.search(searchFilter=f"(sAMAccountName={escape_filter_chars(value)})", attributes=["distinguishedName"])
        if self.connection.last_search_error:
            self.errors.append(self.connection.last_search_error)
            return None
        records = parse_result_attributes(response)
        if len(records) != 1 or not records[0].get("distinguishedName"):
            self.errors.append(f"Expected one directory object for {value}; found {len(records)}")
            return None
        return records[0]["distinguishedName"]

    def modify_group_ldap(self):
        self.data.user_dn = self.find_object_dn(self.target_user)
        if self.data.user_dn is None:
            return
        self.data.group_dn = self.find_object_dn(self.group)
        if self.data.group_dn is None:
            return
        try:
            acknowledged = self.connection.ldap_connection.modify(self.data.group_dn, {"member": [(MODIFY_DELETE if self.remove else MODIFY_ADD, [self.data.user_dn])]})
            self.data.completed = acknowledged is True
            if not self.data.completed:
                self.errors.append("LDAP membership change was not acknowledged")
        except Exception as e:
            self.errors.append(str(e) or type(e).__name__)
