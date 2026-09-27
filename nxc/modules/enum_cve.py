from dataclasses import dataclass
from nxc.playbooks.results import ActionResult, ResultStatus
from impacket.dcerpc.v5 import rrp
from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection


class NXCModule:
    """
    Initial module by: Mauriceter
    Additional authors: azoxlpf, Defte, YOLOP0wn, pol4ir, NeffIsBack
    """
    name = "enum_cve"
    description = "Enumerate common (useful) CVEs by querying the registry for the OS version and UBR."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        os_version: tuple
        ubr: int | None
        checks: list[dict]

    result_type = ResultData

    def __init__(self, context=None, module_options=None):
        self.module_options = module_options
        self.cve = "all"
        self.exploitation_details = False

    def options(self, context, module_options):
        """
        Be aware that these checks solely rely on the OS version and UBR reported in the registry,
        and do not check for the actual presence of the vulnerable components or mitigations.
        Test the attack yourself to verify the host is actually vulnerable.

        Currently supported CVEs:
        - CVE-2025-33073 (NTLM Reflection)
        - CVE-2025-58726 (Ghost SPN)
        - CVE-2025-54918 (NTLM MIC Bypass)
        - CVE-2025-53779 (BadSuccessor)
        - CVE-2024-49019 (EKUwu / ESC15)
        - CVE-2026-54121 (Certighost)
        - CVE-2026-27912 (ResetNightmare)

        CVE             Filter for specific CVE number (default: All)
        EXPLOITATION    Also provide sources for exploitation details (default: False)
        """
        self.listener = None
        if "CVE" in module_options:
            self.cve = module_options["CVE"].lower()
        if "EXPLOITATION" in module_options:
            self.exploitation_details = str(module_options["EXPLOITATION"]).lower() in ["true", "1", "yes"]

    def is_vulnerable(self, major, minor, build, ubr, msrc):
        key = (major, minor, build)
        min_patched_ubr = msrc.get(key)
        if min_patched_ubr is None:
            return None  # Unknown product
        if ubr is None:
            return None
        return ubr < min_patched_ubr

    def on_login(self, context, connection):
        version = (connection.server_os_major, connection.server_os_minor, connection.server_os_build)
        checks, errors, handles = [], [], []
        dce, ubr = None, None
        selected = {cve: details for cve, details in self.CVE_PATCHES.items() if self.cve == "all" or self.cve.lower() == cve.lower()}
        try:
            if not selected:
                raise ValueError(f"No patch comparison available for {self.cve}")
            connection.trigger_winreg()
            dce = NXCRPCConnection(connection).connect(r"\winreg", rrp.MSRPC_UUID_RRP)
            root = rrp.hOpenLocalMachine(dce)["phKey"]
            handles.append(root)
            key = rrp.hBaseRegOpenKey(dce, root, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")["phkResult"]
            handles.append(key)
            registry_type, observed = rrp.hBaseRegQueryValue(dce, key, "UBR")
            if registry_type != rrp.REG_DWORD or not isinstance(observed, int):
                raise ValueError("UBR is not a DWORD revision")
            ubr = observed
            dc = connection.is_host_dc() if any(item.get("dc_only") for item in selected.values()) else None
            for cve, details in selected.items():
                threshold = details["patches"].get(version)
                row = {"cve": cve, "alias": details["alias"], "minimum_patched_ubr": threshold,
                       "below_patch_threshold": None, "status": "unknown", "reason": None,
                       "dc_only": bool(details.get("dc_only")), "is_dc": dc, "signing_required": None}
                checks.append(row)
                if details.get("dc_only") and dc is False:
                    row.update(status="skipped", reason="Only applicable to Domain Controllers")
                elif details.get("dc_only") and dc is None:
                    row["reason"] = "Domain Controller role could not be determined"
                    errors.append(f"{cve}: {row['reason']}")
                elif threshold is None:
                    row["reason"] = f"No patch threshold for OS build {version}"
                    errors.append(f"{cve}: {row['reason']}")
                else:
                    row["below_patch_threshold"] = ubr < threshold
                    row["status"] = "below_threshold" if ubr < threshold else "at_or_above_threshold"
                    if ubr < threshold and "signing_message" in details:
                        row["signing_required"] = connection.conn.isSigningRequired()
                    context.log.highlight(f"{cve} - {details['alias']}: UBR {ubr}, patch threshold {threshold} ({row['status']})")
                    if self.exploitation_details:
                        context.log.highlight(f"Exploitation details: {details['exploitation']}")
                if row["reason"]:
                    context.log.info(f"{cve}: {row['reason']}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        finally:
            for handle in reversed(handles):
                try:
                    rrp.hBaseRegCloseKey(dce, handle)
                except Exception as e:
                    errors.append(f"Closing registry handle: {e}")
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception as e:
                    errors.append(f"Disconnecting registry RPC: {e}")
        for error in errors:
            context.log.fail(error)
        status = ResultStatus.FAILED if errors else ResultStatus.SUCCESS if any(row["below_patch_threshold"] for row in checks) else ResultStatus.SKIPPED if all(row["status"] == "skipped" for row in checks) else ResultStatus.NEGATIVE
        return ActionResult("smb", self.name, connection.host, status, self.ResultData(version, ubr, checks), error="; ".join(errors) or None)

    # patches: key = (major, minor, build), value = minimum patched UBR
    CVE_PATCHES = {
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073
        "CVE-2025-33073": {
            "alias": "NTLM reflection",
            "patches": {
                (10, 0, 10240): 21034,    # Windows 10 1507
                (10, 0, 14393): 8148,     # Windows Server 2016 / Win10 1607
                (10, 0, 17763): 7434,     # Windows Server 2019 / Win10 1809
                (10, 0, 19044): 5965,     # Windows 10 21H2
                (10, 0, 20348): 3807,     # Windows Server 2022
                (10, 0, 22621): 5472,     # Windows 11 22H2
                (10, 0, 25398): 1665,     # Windows Server 2022 23H2
                (10, 0, 26100): 4270,     # Windows Server 2025 / Win11 24H2
            },
            "message": "Relay possible from SMB to any protocol",
            "signing_message": "can relay SMB to other protocols except SMB",
            "exploitation": "https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025",
        },
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-58726
        "CVE-2025-58726": {
            "alias": "Ghost SPN",
            "patches": {
                (6, 0, 6003): 23571,      # Windows Server 2008 SP2
                (6, 1, 7601): 27974,      # Windows Server 2008 R2 SP1
                (6, 2, 9200): 25722,      # Windows Server 2012
                (6, 3, 9600): 22824,      # Windows Server 2012 R2
                (10, 0, 10240): 21161,    # Windows 10 1507
                (10, 0, 14393): 8519,     # Windows Server 2016 / Win10 1607
                (10, 0, 17763): 7919,     # Windows Server 2019 / Win10 1809
                (10, 0, 19044): 6456,     # Windows 10 21H2
                (10, 0, 20348): 4294,     # Windows Server 2022
                (10, 0, 22621): 6060,     # Windows 11 22H2
                (10, 0, 25398): 1913,     # Windows Server 2022 23H2
                (10, 0, 26100): 6899,     # Windows Server 2025 / Win11 24H2
                (10, 0, 26200): 6899,     # Windows 11 25H2
            },
            "message": "Relay possible from SMB using Ghost SPN for Kerberos reflection",
            "signing_message": "Relay possible from SMB using Ghost SPN (non HOST/CIFS) for Kerberos reflection to other protocols except SMB",
            "exploitation": "https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation/",
        },

        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-54918
        # https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/
        "CVE-2025-54918": {
            "alias": "NTLM MIC Bypass",
            "dc_only": True,
            "patches": {
                (6, 0, 6003): 23529,      # Windows Server 2008 SP2
                (6, 1, 7601): 27929,      # Windows Server 2008 R2 SP1
                (6, 2, 9200): 25675,      # Windows Server 2012
                (6, 3, 9600): 22774,      # Windows Server 2012 R2
                (10, 0, 10240): 21128,    # Windows 10 1507
                (10, 0, 14393): 8422,     # Windows Server 2016
                (10, 0, 17763): 7792,     # Windows Server 2019 / Win10 1809
                (10, 0, 19044): 6332,     # Windows 10 21H2
                (10, 0, 20348): 4171,     # Windows Server 2022
                (10, 0, 22621): 5909,     # Windows 11 22H2
                (10, 0, 22631): 5909,     # Windows 11 23H2
                (10, 0, 26100): 6508,     # Windows Server 2025 / Win11 24H2
            },
            "message": "Note that without CVE-2025-33073 only Windows Server 2025 is exploitable",
            "exploitation": "https://yousofnahya.medium.com/hands-on-exploitation-of-cve-2025-54918-cf376ebb40e1",
        },
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779
        "CVE-2025-53779": {
            "alias": "BadSuccessor",
            "dc_only": True,
            "patches": {
                (10, 0, 26100): 4851,     # Windows Server 2025 / Win11 24H2
            },
            "message": "Escalation to Domain Admin possible via dMSA Kerberos abuse",
            "exploitation": "https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory",
        },
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019
        "CVE-2024-49019": {
            "alias": "ESC15 / EKUwu",
            "patches": {
                (6, 0, 6003): 22966,      # Windows Server 2008 SP2
                (6, 1, 7601): 27415,      # Windows Server 2008 R2 SP1
                (6, 2, 9200): 25165,      # Windows Server 2012
                (6, 3, 9600): 22267,      # Windows Server 2012 R2
                (10, 0, 14393): 7515,     # Windows Server 2016
                (10, 0, 17763): 6532,     # Windows Server 2019 / Win10 1809
                (10, 0, 20348): 2849,     # Windows Server 2022
                (10, 0, 25398): 1251,     # Windows Server 2022 23H2
                (10, 0, 26100): 2314,     # Windows Server 2025 / Win11 24H2
            },
            "message": "If host is an AD CS / CA server, it may be vulnerable to ESC15",
            "exploitation": "https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc",
        },
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121
        "CVE-2026-54121": {
            "alias": "Certighost",
            "patches": {
                (6, 2, 9200): 26226,      # Windows Server 2012
                (6, 3, 9600): 23291,      # Windows Server 2012 R2
                (10, 0, 14393): 9339,     # Windows Server 2016
                (10, 0, 17763): 9020,     # Windows Server 2019
                (10, 0, 20348): 5386,     # Windows Server 2022
                (10, 0, 26100): 33158,    # Windows Server 2025
            },
            "message": "If host is an AD CS / CA server, it may be vulnerable to Certighost",
            "exploitation": "https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26",
        },
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27912
        "CVE-2026-27912": {
            "alias": "ResetNightmare",
            "dc_only": True,
            "patches": {
                (6, 2, 9200): 26026,      # Windows Server 2012
                (6, 3, 9600): 23132,      # Windows Server 2012 R2
                (10, 0, 14393): 9060,     # Windows Server 2016
                (10, 0, 17763): 8644,     # Windows Server 2019
                (10, 0, 20348): 5020,     # Windows Server 2022
                (10, 0, 25398): 2274,     # Windows Server 2022 23H2
                (10, 0, 26100): 32690,    # Windows Server 2025
            },
            "message": "Password reset of any account possible via Kerberos change password abuse",
            "exploitation": "https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/",
        },
    }
