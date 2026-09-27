from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.protocols.smb.remotefile import RemoteFile
from impacket import nt_errors
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSError
import contextlib
from dataclasses import dataclass


class NXCModule:
    """
    Enumerate whether the WebClient service is running on the target by looking for the
    DAV RPC Service pipe. This technique was first suggested by Lee Christensen (@tifkin_)

    Module by Tobias Neitzel (@qtc_de)
    Modified by @azoxlpf to handle transport errors gracefully and avoid session crash
    """

    name = "webdav"
    description = "Checks whether the WebClient service is running on the target"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        enabled: bool
        remote_host: str | None

    result_type = ResultData

    def options(self, context, module_options):
        """MSG     Info message when the WebClient service is running. '{}' is replaced by the target."""
        self.output = "WebClient Service enabled on: {}"

        if "MSG" in module_options:
            self.output = module_options["MSG"]

    def on_login(self, context, connection):
        """
        Check whether the 'DAV RPC Service' pipe exists within the 'IPC$' share. This indicates
        that the WebClient service is running on the target.
        """
        try:
            remote_file = RemoteFile(connection.conn, "DAV RPC Service", "IPC$", access=FILE_READ_DATA)
            remote_file.open_file()

            remote_host = connection.conn.getRemoteHost()
            context.log.highlight(self.output.format(remote_host))
            return ActionResult(connection.args.protocol, self.name, connection.host, ResultStatus.SUCCESS, self.ResultData(True, remote_host))
        except SessionError as e:
            if e.getErrorCode() == nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                return ActionResult(connection.args.protocol, self.name, connection.host, ResultStatus.NEGATIVE, self.ResultData(False, None))
            elif e.getErrorCode() in nt_errors.ERROR_MESSAGES:
                context.log.fail(f"Error enumerating WebDAV: {e.getErrorString()[0]}", color="magenta")
            else:
                context.log.debug(f"WebDAV SessionError (code={hex(e.getErrorCode())})")
            return ActionResult(connection.args.protocol, self.name, connection.host, ResultStatus.FAILED, self.ResultData(False, None), error=str(e))
        except (BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as e:
            context.log.debug(f"WebDAV check aborted due to transport error: {e.__class__.__name__}: {e}")
            return ActionResult(connection.args.protocol, self.name, connection.host, ResultStatus.FAILED, self.ResultData(False, None), error=str(e))
        finally:
            with contextlib.suppress(Exception):
                remote_file.close()
