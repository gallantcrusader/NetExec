"""Offline AWS file discovery over shared sessions."""

from importlib import import_module
from io import BytesIO
import json
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("protocol", ["smb", "winrm"])
@pytest.mark.parametrize("outcome", ["found", "empty", "partial", "invalid"])
def test_windows_discovery(protocol, outcome):
    module = import_module("nxc.modules.aws-credentials").NXCModule()
    module.options(None, {})
    paths = [] if outcome == "empty" else ["C:\\Users\\alice\\credentials"]
    output = "" if outcome == "invalid" else json.dumps({"paths": paths, "errors": ["access denied"] if outcome == "partial" else []})
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol=protocol), execute=Mock(return_value=output))
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, protocol, conn.host)
    assert result.status is (ResultStatus.FAILED if outcome in ("partial", "invalid") else ResultStatus.SUCCESS if paths else ResultStatus.NEGATIVE)
    assert result.data.paths == ([] if outcome == "invalid" else paths)
    assert result.data.output == output


@pytest.mark.parametrize("failure", [None, "denied", "cleanup"])
def test_sftp_discovery_does_not_follow_symlinks(failure):
    module = import_module("nxc.modules.aws-credentials").NXCModule()
    module.options(None, {"SEARCH_PATH_LINUX": "'/home/alice space'"})
    base = "/home/alice space"
    sftp = Mock()
    modes = {base: stat.S_IFDIR, base + "/credentials": stat.S_IFREG, base + "/link": stat.S_IFLNK, base + "/other": stat.S_IFREG}
    sftp.lstat.side_effect = lambda path: SimpleNamespace(st_mode=modes[path])
    sftp.listdir_attr.return_value = [SimpleNamespace(filename=name) for name in ["credentials", "link", "other"]]
    if failure == "denied":
        sftp.open.side_effect = PermissionError("denied")
    else:
        sftp.open.return_value = BytesIO(b"[default]\naws_access_key_id=example\n")
    if failure == "cleanup":
        sftp.close.side_effect = RuntimeError("cleanup failed")
    shared = Mock(open_sftp=Mock(return_value=sftp))
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol="ssh"), conn=shared)
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "ssh", conn.host)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.paths == ([] if failure == "denied" else [base + "/credentials"])
    sftp.open.assert_called_once_with(base + "/credentials", "rb")
    sftp.close.assert_called_once_with()
    shared.close.assert_not_called()
