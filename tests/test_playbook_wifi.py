"""Offline Wi-Fi profiles retain raw XML, partial records and secret values."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules import wifi as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def file_entry(name, directory=False):
    return SimpleNamespace(get_longname=lambda: name, is_directory=lambda: directory)


def profile(auth="WPA2PSK", protected="true"):
    return f'<WLANProfile xmlns="urn:test"><SSIDConfig><SSID><name>Example</name></SSID></SSIDConfig><MSM><security><authEncryption><authentication>{auth}</authentication><encryption>AES</encryption></authEncryption><sharedKey><protected>{protected}</protected><keyMaterial>4142</keyMaterial></sharedKey></security></MSM></WLANProfile>'.encode()


@pytest.mark.parametrize("protocol", ["smb", "wmi", "winrm", "mssql"])
@pytest.mark.parametrize("scenario", ["normal", "no_key", "open", "eap", "plain", "parse", "read", "empty"])
def test_wifi_profiles(monkeypatch, protocol, scenario):
    raw = b"invalid XML" if scenario == "parse" else profile("OPEN" if scenario == "open" else "WPA2" if scenario == "eap" else "WPA2PSK", "false" if scenario == "plain" else "true")
    shared = Mock()
    shared.list_dir.side_effect = [[]] if scenario == "empty" else [[file_entry("interface", True)], [file_entry("profile.xml")]]
    shared.read_file.return_value = None if scenario == "read" else raw
    triage = SimpleNamespace(masterkeys=[object()], conn=shared, share="C$", system_wifi_generic_path="interfaces", false_positive=[".", ".."], looted_files={}, triage_eap_creds=Mock(return_value=(b"alice", b"EXAMPLE", b"password")))
    factory = Mock(return_value=triage)
    monkeypatch.setattr(code, "WifiTriage", factory)

    def eap_lookup(triage, profile, observation):
        credentials = {"username": b"alice", "domain": b"EXAMPLE", "password": b"password"}
        observation.update(status="recovered", credentials=credentials)
        return credentials
    monkeypatch.setattr(code, "recover_eap_credentials", eap_lookup)
    monkeypatch.setattr(code, "find_masterkey_for_blob", Mock(return_value=None if scenario == "no_key" else object()))
    monkeypatch.setattr(code, "decrypt_blob", Mock(return_value=b"CaseSensitive\x00"))
    dpapi = SimpleNamespace(conn=shared, target=object(), collect_masterkeys_from_target=Mock(return_value=[] if scenario in ("no_key", "open") else [object()]), log_secret=Mock())
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol=protocol), dpapi_triage=dpapi)
    module = code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, protocol, conn.host)
    failed = scenario in ("no_key", "parse", "read")
    assert result.status is (ResultStatus.FAILED if failed else ResultStatus.NEGATIVE if scenario == "empty" else ResultStatus.SUCCESS)
    assert result.data.enumeration_complete is (not failed)
    if scenario != "empty":
        record = result.data.profiles[0]
        assert record["xml"] == (None if scenario == "read" else raw)
        assert bool(record["error"]) == failed
        if scenario == "normal":
            assert record["password"] == b"CaseSensitive"
        elif scenario == "plain":
            assert record["password"] == "4142"
        elif scenario == "eap":
            assert record["eap_credentials"]["domain"] == b"EXAMPLE"
            assert record["eap_lookup_status"] == "recovered"
            dpapi.collect_masterkeys_from_target.assert_any_call(dump_users=True, dump_system=False)
            assert result.data.user_masterkeys_collected
    assert factory.call_args.kwargs["conn"] is shared
    shared.close.assert_not_called()
