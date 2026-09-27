from dataclasses import dataclass
from io import BytesIO

import pylnk3
from impacket.nt_errors import STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    # Module by @Defte_
    name = "recent_files"
    description = "Extracts recently modified files"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]

    @dataclass
    class ResultData:
        shortcuts: list[dict]
        paths: list[str]
        queried_users: list[str]

    result_type = ResultData

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        records, paths, queried_users, errors = [], [], [], []
        ignored = {name.casefold() for name in self.false_positive}
        try:
            for directory in connection.conn.listPath("C$", "Users\\*"):
                user = directory.get_longname()
                if user.casefold() in ignored or not directory.is_directory():
                    continue
                recent_dir = f"Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"
                queried_users.append(user)
                context.log.highlight(f"C:\\Users\\{user}")
                try:
                    files = connection.conn.listPath("C$", f"{recent_dir}*")
                except SessionError as e:
                    if e.getErrorCode() in (STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND):
                        continue
                    raise
                for file in files:
                    name = file.get_longname()
                    if name.casefold() in ignored or file.is_directory():
                        continue
                    record = {"user": user, "path": recent_dir + name, "content": b"", "downloaded": False, "parsed": False, "target": None, "error": None}
                    records.append(record)
                    with BytesIO() as buffer:
                        try:
                            connection.conn.getFile("C$", record["path"], buffer.write)
                            record["downloaded"] = True
                            buffer.seek(0)
                            record["target"] = pylnk3.parse(buffer).path
                            record["parsed"] = True
                        except Exception as e:
                            record["error"] = str(e) or type(e).__name__
                            raise
                        finally:
                            record["content"] = buffer.getvalue()
                    if record["target"] and record["target"] not in paths:
                        paths.append(record["target"])
                        context.log.highlight(f"\t{record['target']}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
            context.log.fail(errors[-1])
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if records else ResultStatus.NEGATIVE,
            self.ResultData(records, paths, queried_users), error="; ".join(errors) or None,
        )
