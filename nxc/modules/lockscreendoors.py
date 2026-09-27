from dataclasses import dataclass
from io import BytesIO

from nxc.playbooks.results import ActionResult, ResultStatus
import pefile
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module for detecting Windows lock screen backdoors
    Module by @E1A
    """

    name = "lockscreendoors"
    description = "Detect Windows lock screen backdoors by checking FileDescriptions of accessibility binaries."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        files: list[dict]

    result_type = ResultData

    def __init__(self):
        # List of exe names with expected descriptions
        self.expected_descriptions = {
            "utilman.exe": ["Utility Manager"],
            "narrator.exe": ["Screen Reader", "Narrator"],
            "sethc.exe": ["Accessibility shortcut keys"],
            "osk.exe": ["Accessibility On-Screen Keyboard"],
            "magnify.exe": ["Microsoft Screen Magnifier"],
            "EaseOfAccessDialog.exe": ["Ease of Access Dialog Host"],
            "voiceaccess.exe": ["Voice access"],  # Only on Windows 11 / Server 2025+
            "displayswitch.exe": ["Display Switch"],
            "atbroker.exe": ["Windows Assistive Technology Manager", "Transitions Accessible technologies between desktops"],
        }

        # If description matches one of these it's almost certainly backdoored
        self.backdoor_descriptions = [
            "Windows Command Processor",
            "Windows PowerShell"
        ]

    def options(self, context, module_options):
        """No options available"""

    def get_description(self, binary_data):
        self.description_error = None
        pe = None
        description = None
        try:
            pe = pefile.PE(data=binary_data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            for fileinfo in getattr(pe, "FileInfo", []):
                for entry in fileinfo:
                    if entry.Key.decode() == "StringFileInfo":
                        for table in entry.StringTable:
                            value = table.entries.get(b"FileDescription")
                            if value:
                                description = value.decode().strip()
                                break
        except Exception as e:
            self.description_error = str(e) or type(e).__name__
        finally:
            if pe is not None:
                pe.close()
        return description

    def on_admin_login(self, context, connection):
        records = []
        errors = []
        for exe, expected in self.expected_descriptions.items():
            path = rf"\Windows\System32\{exe}"
            record = {"path": path, "description": None, "expected_descriptions": expected, "matches_expected": None, "matches_shell_description": None, "error": None}
            records.append(record)
            try:
                with BytesIO() as buffer:
                    connection.conn.getFile("C$", path, buffer.write)
                    description = self.get_description(buffer.getvalue())
                record["description"] = description
                if self.description_error or not description:
                    raise ValueError(self.description_error or "No FileDescription found")
                record["matches_expected"] = description in expected
                record["matches_shell_description"] = description in self.backdoor_descriptions
                if not record["matches_expected"]:
                    context.log.highlight(f"SUSPICIOUS: {exe} has FileDescription '{description}'")
            except Exception as e:
                record["error"] = str(e) or type(e).__name__
                errors.append(f"{exe}: {record['error']}")
                context.log.fail(errors[-1])
        suspicious = any(record["matches_expected"] is False for record in records)
        if not errors and not suspicious:
            context.log.display("All checked executable descriptions match the expected values")
        return ActionResult(
            "smb", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if suspicious else ResultStatus.NEGATIVE,
            self.ResultData(records), error="; ".join(errors) or None,
        )
