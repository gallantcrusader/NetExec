from dataclasses import dataclass
from io import BytesIO
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus
from pathlib import Path
from nxc.paths import NXC_PATH
from nxc.config import process_secret
from nxc.connection import connection
from nxc.helpers.logger import highlight
from nxc.logger import NXCAdapter
from ftplib import FTP, error_perm, error_temp, all_errors as ftp_errors


@dataclass
class FTPListingData:
    directory: str
    lines: list[str]


@dataclass
class FTPContentData:
    path: str
    content: bytes


@dataclass
class FTPTransferData:
    remote_path: str
    local_path: Path
    bytes_transferred: int
    completed: bool


class ftp(connection):
    def __init__(self, args, db, host, defer_flow=False):
        self.protocol = "FTP"
        self.welcome_banner = ""

        super().__init__(args, db, host, defer_flow=defer_flow)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "FTP",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def enum_host_info(self):
        welcome = self.conn.getwelcome()
        self.logger.debug(f"Welcome result: {welcome}")
        for line in welcome.splitlines():
            self.welcome_banner += line.split("220", 1)[1].strip()  # strip out the extra space in the front
        self.logger.debug(f"Remote version: {self.welcome_banner}")

    def print_host_info(self):
        self.logger.display(f"Banner: {self.welcome_banner}")

    def create_conn_obj(self):
        self.conn = FTP()
        try:
            self.conn.connect(host=self.host, port=self.port)
        except Exception as e:
            self.logger.debug(f"Error connecting to FTP host: {e}")
            return False
        return True

    def plaintext_login(self, username, password):
        if not self.conn.sock:
            self.create_conn_obj()
        try:
            self.logger.debug(self.conn.sock)
            resp = self.conn.login(user=username, passwd=password)
            self.logger.debug(f"Response: {resp}")
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} (Response:{e})")
            return False

        # 230 is "User logged in, proceed" response, ftplib raises an exception on failed login
        if "230" in resp:
            self.logger.debug(f"Host: {self.host} Port: {self.port}")
            self.db.add_host(self.host, self.port, self.welcome_banner)

            cred_id = self.db.add_credential(username, password)

            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(cred_id, host_id)

            if username in ["anonymous", ""]:
                self.logger.success(f"{username}:{process_secret(password)} {highlight('- Anonymous Login!')}")
            else:
                self.logger.success(f"{username}:{process_secret(password)}")

        if not self.args.continue_on_success:
            return True

    def disconnect(self):
        self.conn.close()

    def ls(self):
        directory = self.args.ls or "."
        original_directory = None
        lines = []
        errors = []
        try:
            if directory != ".":
                original_directory = self.conn.pwd()
                self.conn.cwd(directory)
            self.conn.retrlines("LIST -a", callback=lines.append)
            self.logger.display(f"Directory Listing for {directory}")
            for line in lines:
                self.logger.highlight(line)
        except (error_perm, error_temp, OSError) as e:
            errors.append(str(e))
            self.logger.fail(f"Failed to list directory: {e}")
        finally:
            if original_directory is not None:
                try:
                    self.conn.cwd(original_directory)
                except (error_perm, error_temp, OSError) as e:
                    errors.append(f"Restoring FTP directory: {e}")
        if self.playbook_mode:
            return ActionResult("ftp", "ls", self.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if lines else ResultStatus.NEGATIVE, FTPListingData(directory, lines), error="; ".join(errors) if errors else None)

    def list_directory_full(self):
        # in the future we can use mlsd/nlst if we want, but this gives a full output like `ls -la`
        # ftplib's "dir" prints directly to stdout, and "nlst" only returns the folder name, not full details
        files = []
        try:
            self.conn.retrlines("LIST -a", callback=files.append)
        except error_perm as error_message:
            self.logger.fail(f"Failed to list directory. Response: ({error_message})")
            self.conn.close()
            return False
        except error_temp as e:
            self.logger.fail(e)
            self.conn.close()
            return False
        return files

    def get(self):
        return self.get_file(self.args.get)

    def put(self):
        return self.put_file(*self.args.put)

    def get_file(self, filename):
        output = getattr(self.args, "get_output", None)
        local_path = Path(output).expanduser() if output else Path(NXC_PATH) / "downloads" / "ftp" / self.host.replace(":", "_") / filename.split("/")[-1]
        transferred = 0
        created = False
        error = None
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            with local_path.open("wb") as file:
                created = True

                def write_block(block):
                    nonlocal transferred
                    transferred += file.write(block)

                self.conn.retrbinary(f"RETR {filename}", write_block)
            self.logger.success(f"Downloaded: {filename} to {local_path}")
        except ftp_errors as e:
            error = str(e) or type(e).__name__
            self.logger.fail(f"Failed to download {filename}: {error}")
        if self.playbook_mode:
            return ActionResult(
                "ftp", "get", self.host, ResultStatus.FAILED if error else ResultStatus.SUCCESS,
                FTPTransferData(filename, local_path, transferred, error is None),
                artifacts=[Artifact(local_path, "partial_download" if error else "download")] if created else [], error=error,
            )
        return False if error else None

    def put_file(self, local_file, remote_file):
        local_path = Path(local_file).expanduser()
        transferred = 0
        error = None

        def sent_block(block):
            nonlocal transferred
            transferred += len(block)

        try:
            with local_path.open("rb") as file:
                self.conn.storbinary(f"STOR {remote_file}", file, callback=sent_block)
            self.logger.success(f"Uploaded: {local_path} to {remote_file}")
        except ftp_errors as e:
            error = str(e) or type(e).__name__
            self.logger.fail(f"Failed to upload {local_path}: {error}")
        if self.playbook_mode:
            return ActionResult("ftp", "put", self.host, ResultStatus.FAILED if error else ResultStatus.SUCCESS, FTPTransferData(remote_file, local_path, transferred, error is None), error=error)
        return False if error else None

    def cat(self):
        remote_file = self.args.cat
        buf = BytesIO()
        error = None
        try:
            if self.conn.encoding == "utf-8":
                self.conn.sendcmd("TYPE I")
            self.conn.retrbinary(f"RETR {remote_file}", buf.write)
        except (error_perm, error_temp, OSError) as e:
            error = str(e)
            self.logger.fail(f"Failed to get file content: {e}")
        if error is None:
            try:
                for line in buf.getvalue().decode().splitlines():
                    self.logger.highlight(line)
            except UnicodeDecodeError as e:
                self.logger.display(f"Binary content cannot be displayed as UTF-8: {e}")
        if self.playbook_mode:
            return ActionResult("ftp", "cat", self.host, ResultStatus.FAILED if error else ResultStatus.SUCCESS, FTPContentData(remote_file, buf.getvalue()), error=error)
        return False if error else None

    def supported_commands(self):
        raw_supported_commands = self.conn.sendcmd("HELP")
        supported_commands = [item for sublist in (x.split() for x in raw_supported_commands.split("\n")[1:-1]) for item in sublist]
        self.logger.debug(f"Supported commands: {supported_commands}")
        return supported_commands
