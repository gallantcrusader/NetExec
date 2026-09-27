# everything is comming from https://github.com/ly4k/SMBGhost
# credit to @ly4k_
# module by : @r4vanan
import socket
import struct
from dataclasses import dataclass
from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus

# Constants
MAX_ATTEMPTS = 2000  # False negative chance: 0.04%

# SMBGhost Packet
SMBGHOST_PKT = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'


class NXCModule:
    name = "smbghost"
    description = "Module to check for the SMB dialect 3.1.1 and compression capability of the host, which is an indicator for the SMBGhost vulnerability (CVE-2020-0796)."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        potentially_vulnerable: bool

    result_type = ResultData

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        # Define options if needed
        pass

    def on_login(self, context, connection):
        self.context = context
        self.last_error = None
        vulnerable = self.perform_attack(connection.host)
        if vulnerable:
            self.context.log.highlight("Potentially vulnerable to SMBGhost (CVE-2020-0796)")
        return ActionResult(
            connection.args.protocol,
            self.name,
            connection.host,
            ResultStatus.FAILED if self.last_error else ResultStatus.SUCCESS if vulnerable else ResultStatus.NEGATIVE,
            self.ResultData(vulnerable),
            error=self.last_error,
        )

    def perform_attack(self, target_ip):
        self.context.log.debug("Performing SMBGhost check...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((target_ip, 445))
                sock.send(SMBGHOST_PKT)

                # Receive the first 4 bytes for length
                nb_data = sock.recv(4)
                if len(nb_data) < 4:
                    self.last_error = "Connection closed before SMBGhost response length"
                    self.context.log.debug(f"{target_ip} Connection closed unexpectedly.")
                    return False

                nb, = struct.unpack(">I", nb_data)
                res = sock.recv(nb)
                if len(res) < 72:
                    self.last_error = "SMBGhost response was incomplete"
                    self.context.log.debug(f"{target_ip} returned an incomplete SMBGhost response.")
                    return False

                # Check response for vulnerability
                if res[68:70] == b"\x11\x03" and res[70:72] == b"\x02\x00":
                    return True
                else:
                    self.context.log.debug(f"{target_ip} Not vulnerable.")
                    return False
        except Exception as e:
            self.last_error = str(e) or type(e).__name__
            self.context.log.fail(f"Error while connecting to host: {e}")
            return False
