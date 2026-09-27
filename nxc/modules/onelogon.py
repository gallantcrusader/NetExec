import csv
from configparser import ConfigParser
from dataclasses import dataclass, field
from io import BytesIO

from impacket.nt_errors import STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from nxc.helpers.registry import RegistryValue, read_registry_value
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Module by @NeffIsBack. Inventory Onelogon-related configuration."""

    name = "onelogon"
    description = "Scan GPOs and registry for machine accounts vulnerable to Onelogon"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION
    registry_key = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    registry_name = "VulnerableChannelAllowList"

    @dataclass
    class ResultData:
        source: str
        policies: list[dict] = field(default_factory=list)
        registry: RegistryValue | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        data = self.ResultData("sysvol")
        errors = []
        base = f"{connection.targetDomain}/Policies"
        try:
            for policy in connection.conn.listPath("SYSVOL", f"{base}/*"):
                name = policy.get_longname()
                if name in (".", "..") or not policy.is_directory():
                    continue
                record = {"name": name, "path": f"{base}/{name}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf", "content": b"", "complete": False, "matches": [], "error": None}
                with BytesIO() as buffer:
                    try:
                        connection.conn.getFile("SYSVOL", record["path"], buffer.write)
                        record["complete"] = True
                    except SessionError as e:
                        if e.getErrorCode() in (STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND) and not buffer.getvalue():
                            continue
                        record["error"] = str(e)
                        raise
                    except Exception as e:
                        record["error"] = str(e) or type(e).__name__
                        raise
                    finally:
                        record["content"] = buffer.getvalue()
                        if record["complete"] or record["error"]:
                            data.policies.append(record)
                try:
                    content = record["content"]
                    text = content.decode("utf-16") if content.startswith((b"\xff\xfe", b"\xfe\xff")) else content.decode("utf-8-sig")
                    parser = ConfigParser(strict=False, interpolation=None, allow_no_value=True)
                    parser.optionxform = str
                    parser.read_string(text)
                    for section in parser.sections():
                        for key, value in parser.items(section):
                            if key.casefold() == f"MACHINE\\{self.registry_key}\\{self.registry_name}".casefold():
                                match = {"section": section, "key": key, "raw_value": value, "fields": []}
                                record["matches"].append(match)
                                match["fields"] = next(csv.reader([value]))
                                context.log.highlight(f"Policy {name}: {self.registry_name} = {value}")
                except Exception as e:
                    record["error"] = str(e) or type(e).__name__
                    raise
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
            context.log.fail(errors[-1])
        return ActionResult("smb", self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if any(policy["matches"] for policy in data.policies) else ResultStatus.NEGATIVE, data, error="; ".join(errors) or None)

    def on_admin_login(self, context, connection):
        value = read_registry_value(connection, self.registry_key, self.registry_name)
        if value.error:
            context.log.fail(value.error)
        elif value.present:
            context.log.highlight(f"{self.registry_name}: {value.value}")
        else:
            context.log.display(f"{self.registry_name} is not present")
        return ActionResult("smb", self.name, connection.host, ResultStatus.FAILED if value.error else ResultStatus.SUCCESS if value.present else ResultStatus.NEGATIVE, self.ResultData("registry", registry=value), error=value.error)
