from dataclasses import dataclass
from sys import exit

from impacket.dcerpc.v5 import samr
from impacket.ldap.ldap import LDAPSessionError, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn
from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Module by CyberCelt: @Cyb3rC3lt
    Refactored to use impacket LDAP CRUD operations instead of ldap3.

    Initial module:
        https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    Thanks to the guys at impacket for the original code
    """

    name = "add-computer"
    description = "Adds or deletes a domain computer via SAMR (SMB) or LDAP"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    @dataclass
    class ResultData:
        account: str
        domain: str
        operation: str
        completed: bool = False
        stored: bool = False
        credential_id: int | None = None
        password: str | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """
        add-computer: Adds, deletes, or changes the password of a domain computer account.
        Uses SAMR when invoked with nxc smb.

        NAME        Computer name (required). Trailing '$' is added automatically.
        PASSWORD    Computer password (required for add/changepw).
        DELETE      Set to delete the computer account.
        CHANGEPW    Set to change an existing computer's password.

        Usage (same syntax for ldap):
            nxc smb  $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" PASSWORD="Password1"
            nxc smb  $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" DELETE=True
            nxc smb  $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" PASSWORD="Password2" CHANGEPW=True
        """
        self.delete = str(module_options.get("DELETE", "False")).lower() == "true"
        self.change_pw = str(module_options.get("CHANGEPW", "False")).lower() == "true"
        name = module_options.get("NAME")
        self.computer_password = module_options.get("PASSWORD")
        if not name or (self.delete and self.change_pw) or (not self.delete and not self.computer_password):
            context.log.fail("NAME and PASSWORD are required for add/change; DELETE and CHANGEPW cannot be combined")
            exit(1)
        self.computer_name = name if name.endswith("$") else name + "$"

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.errors = []
        data = self.ResultData(self.computer_name, connection.domain,
                               "delete" if self.delete else "change_password" if self.change_pw else "add",
                               password=None if self.delete else self.computer_password)
        try:
            data.completed = self.do_samr() if context.protocol == "smb" else self.do_ldap()
            if data.completed:
                self.sync_database(data)
        except Exception as e:
            self.errors.append(str(e) or type(e).__name__)
        for error in self.errors:
            context.log.fail(error)
        if data.completed:
            context.log.success(f"Computer {data.operation} acknowledged for {self.computer_name}")
        return ActionResult(context.protocol, self.name, connection.host,
                            ResultStatus.SUCCESS if data.completed and data.stored and not self.errors else ResultStatus.FAILED,
                            data, error="; ".join(self.errors) or None)

    def failure(self, message):
        self.errors.append(message)
        return False

    def credential_rows(self):
        db = self.context.db
        rows = db.get_user(self.connection.domain, self.computer_name) if hasattr(db, "get_user") else db.get_credentials(filter_term=self.computer_name)
        return [row._mapping for row in rows or []
                if str(row._mapping["domain"]).casefold() == self.connection.domain.casefold()
                and str(row._mapping["username"]).casefold() == self.computer_name.casefold()]

    def sync_database(self, data):
        db = self.context.db
        if self.delete:
            ids = [row["id"] for row in self.credential_rows()]
            if ids:
                db.remove_credentials(ids)
            if self.credential_rows():
                self.failure("Deleted computer credentials remain in the NetExec database")
            else:
                data.stored = True
            return
        if self.change_pw:
            ids = [row["id"] for row in self.credential_rows()]
            if ids:
                db.remove_credentials(ids)
        db.add_credential("plaintext", data.domain, data.account, data.password)
        matches = [row["id"] for row in self.credential_rows()
                   if row["credtype"] == "plaintext" and row["password"] == data.password]
        if len(matches) != 1:
            self.failure("Changed computer credential was not found in the NetExec database")
            return
        data.credential_id = matches[0]
        data.stored = True

    def do_samr(self):
        try:
            dce = NXCRPCConnection(self.connection).connect(r"\samr", samr.MSRPC_UUID_SAMR)
        except Exception as e:
            return self.failure(f"Failed to connect to SAMR: {e}")

        try:
            return self.samr_execute(dce, self.connection.conn.getRemoteName())
        except Exception as e:
            return self.failure(f"SAMR computer operation failed: {e}")
        finally:
            try:
                dce.disconnect()
            except Exception as e:
                self.errors.append(f"Closing SAMR connection: {e}")

    def samr_execute(self, dce, target_name):
        domain = self.connection.domain
        serv_handle = samr.hSamrConnect5(dce, f"\\\\{target_name}\x00", samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN)["ServerHandle"]
        domain_handle = None
        user_handle = None
        try:
            domains = samr.hSamrEnumerateDomainsInSamServer(dce, serv_handle)["Buffer"]["Buffer"]
            non_builtin = [d["Name"] for d in domains if d["Name"].lower() != "builtin"]
            matched = [name for name in non_builtin if name.lower() == domain.lower()]
            selected = non_builtin[0] if len(non_builtin) == 1 else matched[0] if len(matched) == 1 else None
            if selected is None:
                return self.failure(f"Domain '{domain}' not found in SAMR")
            domain_sid = samr.hSamrLookupDomainInSamServer(dce, serv_handle, selected)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(dce, serv_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER, domain_sid)["DomainHandle"]
            if self.delete or self.change_pw:
                user_handle = self.samr_open_existing(dce, domain_handle, selected, self.connection.username)
            else:
                user_handle = self.samr_create(dce, domain_handle, self.connection.username)

            if user_handle is None:
                return False

            if self.delete:
                samr.hSamrDeleteUser(dce, user_handle)
                user_handle = None
            else:
                samr.hSamrSetPasswordInternal4New(dce, user_handle, self.computer_password)
                if not self.change_pw:
                    new_handle = self.samr_set_workstation_trust(dce, domain_handle)
                    old_handle, user_handle = user_handle, new_handle
                    try:
                        samr.hSamrCloseHandle(dce, old_handle)
                    except Exception as e:
                        self.errors.append(f"Closing SAMR initial user handle: {e}")
            return True
        finally:
            if user_handle is not None:
                try:
                    samr.hSamrCloseHandle(dce, user_handle)
                except Exception as e:
                    self.errors.append(f"Closing SAMR user handle: {e}")
            if domain_handle is not None:
                try:
                    samr.hSamrCloseHandle(dce, domain_handle)
                except Exception as e:
                    self.errors.append(f"Closing SAMR domain handle: {e}")
            try:
                samr.hSamrCloseHandle(dce, serv_handle)
            except Exception as e:
                self.errors.append(f"Closing SAMR server handle: {e}")

    def samr_set_workstation_trust(self, dce, domain_handle):
        user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.computer_name])["RelativeIds"]["Element"][0]
        new_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)["UserHandle"]
        try:
            req = samr.SAMPR_USER_INFO_BUFFER()
            req["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
            req["Control"]["UserAccountControl"] = samr.USER_WORKSTATION_TRUST_ACCOUNT
            samr.hSamrSetInformationUser2(dce, new_handle, req)
        except Exception as e:
            samr.hSamrCloseHandle(dce, new_handle)
            raise e
        return new_handle

    def samr_open_existing(self, dce, domain_handle, selected_domain, username):
        try:
            user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.computer_name])["RelativeIds"]["Element"][0]
        except samr.DCERPCSessionError as e:
            if "STATUS_NONE_MAPPED" in str(e):
                self.failure(f"'{self.computer_name}' not found in domain {selected_domain}")
            else:
                self.failure(f"Error looking up {self.computer_name}: {e}")
            return None

        try:
            access = samr.DELETE if self.delete else samr.USER_FORCE_PASSWORD_CHANGE
            return samr.hSamrOpenUser(dce, domain_handle, access, user_rid)["UserHandle"]
        except samr.DCERPCSessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                action = "delete" if self.delete else "change password for"
                self.failure(f"{username} does not have the right to {action} '{self.computer_name}'")
            else:
                self.failure(f"Error opening {self.computer_name}: {e}")
            return None

    def samr_create(self, dce, domain_handle, username):
        try:
            samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.computer_name])
            self.failure(f"Computer '{self.computer_name}' already exists")
            return None
        except samr.DCERPCSessionError as e:
            if "STATUS_NONE_MAPPED" not in str(e):
                self.failure(f"Error looking up {self.computer_name}: {e}")
                return None

        try:
            # Doing this call manually because of weird exception handling in https://github.com/fortra/impacket/blob/084aff60df7e8a5784bee3fb6ac74ed9d1362af8/impacket/dcerpc/v5/samr.py#L2591-L2599
            request = samr.SamrCreateUser2InDomain()
            request["DomainHandle"] = domain_handle
            request["Name"] = self.computer_name
            request["AccountType"] = samr.USER_WORKSTATION_TRUST_ACCOUNT
            request["DesiredAccess"] = samr.USER_FORCE_PASSWORD_CHANGE
            return dce.request(request)["UserHandle"]
        except samr.DCERPCSessionError as e:
            if "STATUS_USER_EXISTS" in str(e):
                self.failure(f"Computer '{self.computer_name}' already exists")
            elif "STATUS_ACCESS_DENIED" in str(e):
                self.failure(f"{username} does not have the right to create a computer account")
            elif "STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED" in str(e):
                self.failure(f"{username} exceeded the machine account quota")
            else:
                self.failure(f"Error creating computer: {e}")
            return None

    def do_ldap(self):
        name = self.computer_name[:-1]
        computer_dn = f"CN={escape_rdn(name)},CN=Computers,{self.connection.baseDN}"

        if self.delete:
            return self.ldap_delete(self.connection.ldap_connection, computer_dn)
        elif self.change_pw:
            return self.ldap_change_password(self.connection.ldap_connection, computer_dn)
        else:
            return self.ldap_add(self.connection.ldap_connection, computer_dn, name)

    def ldap_delete(self, ldap_conn, dn):
        try:
            ldap_conn.delete(dn)
            return True
        except LDAPSessionError as e:
            if "noSuchObject" in str(e):
                return self.failure(f'Computer "{self.computer_name}" was not found')
            elif "insufficientAccessRights" in str(e):
                return self.failure(f'Insufficient rights to delete "{self.computer_name}"')
            else:
                return self.failure(f'Failed to delete "{self.computer_name}": {e}')

    def ldap_change_password(self, ldap_conn, dn):
        try:
            encoded_pw = f'"{self.computer_password}"'.encode("utf-16-le")
            ldap_conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, encoded_pw)]})
            return True
        except LDAPSessionError as e:
            if "noSuchObject" in str(e):
                return self.failure(f'Computer "{self.computer_name}" was not found')
            elif "insufficientAccessRights" in str(e):
                return self.failure(f'Insufficient rights to change password for "{self.computer_name}"')
            elif "unwillingToPerform" in str(e):
                return self.failure(f'Server unwilling to change password for "{self.computer_name}"')
            else:
                return self.failure(f'Failed to change password for "{self.computer_name}": {e}')

    def ldap_add(self, ldap_conn, dn, name):
        fqdn = f"{name}.{self.connection.domain}"
        spns = [
            f"HOST/{name}",
            f"HOST/{fqdn}",
            f"RestrictedKrbHost/{name}",
            f"RestrictedKrbHost/{fqdn}",
        ]

        try:
            ldap_conn.add(
                dn,
                ["top", "person", "organizationalPerson", "user", "computer"],
                {
                    "dnsHostName": fqdn,
                    "userAccountControl": 0x1000,
                    "servicePrincipalName": spns,
                    "sAMAccountName": self.computer_name,
                    "unicodePwd": f'"{self.computer_password}"'.encode("utf-16-le"),
                },
            )
            return True
        except LDAPSessionError as e:
            if "entryAlreadyExists" in str(e):
                return self.failure(f"Computer '{self.computer_name}' already exists")
            elif "insufficientAccessRights" in str(e):
                return self.failure(f"Insufficient rights to add '{self.computer_name}'")
            elif "unwillingToPerform" in str(e):
                return self.failure("Server unwilling to perform")
            elif "constraintViolation" in str(e):
                return self.failure(f"Constraint violation for '{self.computer_name}'. Quota exceeded or password policy.")
            else:
                return self.failure(f"Failed to add '{self.computer_name}': {e}")
