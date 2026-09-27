import json
from dataclasses import dataclass, field

from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "bitlocker"
    description = "Enumerating BitLocker Status on target(s) If it is enabled or disabled."
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        source: str
        volumes: list[dict] = field(default_factory=list)
        records: list[dict] = field(default_factory=list)
        output: str | bytes | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """No options available."""

    def on_admin_login(self, context, connection):
        protocol = connection.args.protocol
        data = self.ResultData("wmi" if protocol == "wmi" else "powershell")
        errors = []
        try:
            if protocol == "wmi":
                result = connection.query_result(
                    "SELECT DriveLetter, ProtectionStatus, EncryptionMethod FROM Win32_EncryptableVolume",
                    "root\\CIMv2\\Security\\MicrosoftVolumeEncryption",
                    auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                )
                data.records = result.data.records
                if result.error:
                    errors.append(result.error)
                for record in data.records:
                    data.volumes.append(self.volume(
                        record.get("DriveLetter", {}).get("value"),
                        record.get("ProtectionStatus", {}).get("value"),
                        record.get("EncryptionMethod", {}).get("value"),
                    ))
            else:
                payload = "$ErrorActionPreference='Stop'; try { $volumes=@(Get-BitLockerVolume | Select-Object MountPoint,@{n='ProtectionStatus';e={[int]$_.ProtectionStatus}},@{n='EncryptionMethod';e={[int]$_.EncryptionMethod}}); @{volumes=$volumes;error=$null} | ConvertTo-Json -Compress -Depth 5 } catch { @{volumes=@();error=$_.Exception.Message} | ConvertTo-Json -Compress -Depth 5 }"
                data.output = connection.execute(f'powershell.exe -NoProfile -Command "{payload}"', True)
                parsed = json.loads(data.output)
                if not isinstance(parsed, dict) or not isinstance(parsed.get("volumes"), list) or "error" not in parsed:
                    raise ValueError("BitLocker command returned an invalid result envelope")
                data.records = parsed["volumes"]
                if parsed["error"]:
                    errors.append(str(parsed["error"]))
                for record in data.records:
                    data.volumes.append(self.volume(record.get("MountPoint"), record.get("ProtectionStatus"), record.get("EncryptionMethod")))
            for volume in data.volumes:
                context.log.highlight(f"{volume['mount_point']}: ProtectionStatus={volume['protection_status']}, EncryptionMethod={volume['encryption_method']}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        for error in errors:
            context.log.fail(error)
        return ActionResult(protocol, self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if data.volumes else ResultStatus.NEGATIVE, data, error="; ".join(errors) or None)

    def volume(self, mount_point, protection_status, encryption_method):
        return {"mount_point": mount_point, "protection_status": protection_status, "encryption_method": encryption_method,
                "protection_enabled": {0: False, 1: True}.get(protection_status)}
