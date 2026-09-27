"""Offline screenshot artifacts and status handling."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from pathlib import Path

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus
from nxc.playbooks.screenshots import capture_screenshot


@pytest.mark.parametrize("protocol", ["rdp", "vnc"])
@pytest.mark.parametrize("outcome", ["saved", "empty", "failure", "missing_file"])
def test_screenshot_action_returns_artifact(tmp_path, protocol, outcome):
    path = tmp_path / "screen.png"
    if outcome == "saved":
        path.write_bytes(b"mock image")
    capture = AsyncMock(return_value=path if outcome in {"saved", "missing_file"} else None)
    if outcome == "failure":
        capture.side_effect = OSError("capture failed")
    module = ProtocolLoader().load_protocol(f"nxc/protocols/{protocol}.py")
    fake = SimpleNamespace(playbook_mode=True, host="offline.invalid", screen=capture)
    result = getattr(module, protocol).screenshot(fake)
    expected = ResultStatus.SUCCESS if outcome == "saved" else ResultStatus.NEGATIVE if outcome == "empty" else ResultStatus.FAILED
    assert result.status is expected
    assert result.data.captured is (outcome == "saved")
    assert len(result.artifacts) == int(outcome == "saved")
    if outcome == "saved":
        assert result.to_dict()["artifacts"][0]["path"] == str(path)
    capture.assert_awaited_once()


def test_capture_error_message_is_retained():
    result = capture_screenshot("rdp", "screenshot", "offline.invalid", AsyncMock(side_effect=OSError("capture failed")))
    assert result.error == "capture failed"


@pytest.mark.parametrize("protocol", ["rdp", "vnc"])
@pytest.mark.parametrize("has_frame", [True, False])
def test_capture_routine_creates_directory_and_cleans_up(tmp_path, monkeypatch, protocol, has_frame):
    module = ProtocolLoader().load_protocol(f"nxc/protocols/{protocol}.py")
    desktop = Mock()
    desktop.save.side_effect = lambda path, image_format: Path(str(path)).write_bytes(b"mock screenshot")
    conn = Mock(desktop_buffer_has_data=has_frame)
    conn.get_desktop_buffer.return_value = desktop
    conn.terminate = AsyncMock()
    monkeypatch.setattr(module, "RDPConnection" if protocol == "rdp" else "VNCConnection", Mock(return_value=conn))
    monkeypatch.setattr(module, "NXC_PATH", tmp_path)
    monkeypatch.setattr(module.asyncio, "sleep", AsyncMock())
    fake = SimpleNamespace(conn=None, auth=object(), credential=object(), target=object(), iosettings=object(), host="offline.invalid", hostname="desktop", logger=Mock(), playbook_mode=True, args=SimpleNamespace(screentime=0, vnc_timeout=2), connect_rdp=AsyncMock(), connect_vnc=AsyncMock(), terminate_conn=AsyncMock())
    fake.screen = lambda: getattr(module, protocol).screen(fake)
    result = getattr(module, protocol).screenshot(fake)
    assert result.data.captured is has_frame
    if has_frame:
        assert result.data.path.parent == tmp_path / "screenshots"
        assert result.data.path.read_bytes() == b"mock screenshot"
    if protocol == "rdp":
        fake.terminate_conn.assert_awaited_once()
    else:
        conn.terminate.assert_awaited_once()


@pytest.mark.parametrize("failure", [False, True])
def test_nla_capture_restores_auth_and_negotiation(tmp_path, failure):
    module = ProtocolLoader().load_protocol("nxc/protocols/rdp.py")
    auth = object()
    path = tmp_path / "nla.png"
    path.write_bytes(b"mock screenshot")
    fake = SimpleNamespace(nla=False, auth=auth, iosettings=SimpleNamespace(supported_protocols="original"), playbook_mode=True, host="offline.invalid")

    def capture():
        fake.auth = "anonymous"
        fake.iosettings.supported_protocols = "temporary"
        if failure:
            raise OSError("capture failed")
        return path

    fake.nla_screen = AsyncMock(side_effect=capture)
    result = module.rdp.nla_screenshot(fake)
    assert result.action == "nla_screenshot"
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert fake.auth is auth
    assert fake.iosettings.supported_protocols == "original"


def test_nla_required_skips_login_screen_capture():
    module = ProtocolLoader().load_protocol("nxc/protocols/rdp.py")
    fake = SimpleNamespace(nla=True, playbook_mode=True, host="offline.invalid", nla_screen=AsyncMock())
    result = module.rdp.nla_screenshot(fake)
    assert result.status is ResultStatus.SKIPPED
    fake.nla_screen.assert_not_called()
