from dataclasses import dataclass
from sys import exit
import json

from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Search for KeePass-related files and process

    Module by @d3lb3
    Inspired by @harmj0y https://raw.githubusercontent.com/GhostPack/KeeThief/master/PowerShell/KeePassConfig.ps1
    """

    name = "keepass_discover"
    description = "Search for KeePass-related files and process."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        processes: list[dict]
        files: list[str]
        processes_queried: bool
        files_queried: bool
        outputs: dict

    result_type = ResultData

    def __init__(self):
        self.search_type = "ALL"
        self.search_path = "'C:\\Users\\',$env:ProgramFiles,${env:ProgramFiles(x86)}"

    def options(self, context, module_options):
        r"""
        SEARCH_TYPE     Specify what to search, between:
                          PROCESS     Look for process names beginning with kee
                          FILES       Look for KeePass-related files (KeePass.config.xml, .kdbx, KeePass.exe) only, may take some time
                          ALL         Look for process names beginning with kee and KeePass-related files (default)

        SEARCH_PATH     Comma-separated remote locations where to search for KeePass-related files (you must add single quotes around the paths if they include spaces)
                        Default: 'C:\\Users\\',$env:ProgramFiles,${env:ProgramFiles(x86)}
        """
        if "SEARCH_PATH" in module_options:
            self.search_path = module_options["SEARCH_PATH"]

        if "SEARCH_TYPE" in module_options:
            self.search_type = module_options["SEARCH_TYPE"].upper()
        if self.search_type not in ("ALL", "PROCESS", "FILES"):
            context.log.fail("SEARCH_TYPE must be ALL, PROCESS, or FILES")
            exit(1)

    def on_admin_login(self, context, connection):
        data = self.ResultData([], [], False, False, {})
        errors = []
        searches = {}
        if self.search_type in ("ALL", "PROCESS"):
            searches["processes"] = "Get-Process -IncludeUserName -ErrorAction SilentlyContinue -ErrorVariable +lookupErrors | Where-Object { $_.ProcessName -like 'kee*' } | Select-Object Id,UserName,ProcessName"
        if self.search_type in ("ALL", "FILES"):
            searches["files"] = f"Get-ChildItem -Path {self.search_path} -Recurse -Force -Include ('KeePass.config.xml','KeePass.exe','*.kdbx') -ErrorAction SilentlyContinue -ErrorVariable +lookupErrors | Where-Object {{ -not $_.PSIsContainer }} | Select-Object -ExpandProperty FullName"
        for kind, search in searches.items():
            setattr(data, f"{kind}_queried", True)
            payload = "$lookupErrors = @(); $records = @(" + search + "); @{records=$records; errors=@($lookupErrors | ForEach-Object { $_.ToString() })} | ConvertTo-Json -Compress -Depth 5"
            try:
                output = connection.execute(f'powershell.exe -NoProfile -Command "{payload}"', True)
                data.outputs[kind] = output
                parsed = json.loads(output)
                if not isinstance(parsed, dict) or not isinstance(parsed.get("records"), list) or not isinstance(parsed.get("errors"), list):
                    raise ValueError("Discovery command returned an invalid result envelope")
                records = parsed["records"]
                if kind == "files" and any(not isinstance(record, str) for record in records):
                    raise ValueError("File discovery returned a non-path record")
                if kind == "processes" and any(not isinstance(record, dict) or not {"Id", "UserName", "ProcessName"} <= record.keys() for record in records):
                    raise ValueError("Process discovery returned an invalid record")
                setattr(data, kind, records)
                errors.extend(f"{kind}: {error}" for error in parsed["errors"])
                for record in records:
                    context.log.highlight(f"Found {kind}: {record}")
            except Exception as e:
                errors.append(f"{kind}: {str(e) or type(e).__name__}")
        for error in errors:
            context.log.fail(error)
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if data.processes or data.files else ResultStatus.NEGATIVE,
            data, error="; ".join(errors) or None,
        )
