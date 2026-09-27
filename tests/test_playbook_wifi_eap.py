"""EAP recovery preserves inconclusive reads and rejects undecrypted fallback bytes."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.helpers import wifi_eap as code


def plaintext(encrypted=False):
    blob = bytearray(480)
    blob[168:176] = b"\x04\x00\x00\x00\x02\x00\x00\x00" if encrypted else b"\x03\x00\x00\x00\x20\x00\x00\x00"
    blob[176:190] = b"alice\x00EXAMPLE\x00"
    blob[432:442] = b"\x00password\x00"
    if encrypted:
        blob.extend(b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01encrypted")
    return bytes(blob)


@pytest.mark.parametrize("scenario", ["plain", "nested", "absent", "denied", "no_key", "nested_key", "decrypt", "layout", "truncated"])
def test_eap_outcomes(monkeypatch, scenario):
    conn = Mock()
    conn.reg_get_key_value.return_value = None if scenario == "absent" else b"encrypted profile"
    if scenario == "denied":
        conn.reg_get_key_value.side_effect = PermissionError("denied")
    triage = SimpleNamespace(conn=conn, users={"alice": "S-1-5-21-1"}, eap_profiles_keys=["Profiles", "UserData"], masterkeys=[object()])
    keys = Mock(return_value=None if scenario == "no_key" else object())
    if scenario == "nested_key":
        keys.side_effect = [object(), None]
    monkeypatch.setattr(code, "find_masterkey_for_blob", keys)
    content = b"unknown" if scenario == "layout" else plaintext(scenario in ("nested", "nested_key"))
    if scenario == "truncated":
        content = content[:200]
    decrypt = Mock(return_value=None if scenario == "decrypt" else content)
    if scenario == "nested":
        decrypt.side_effect = [content, b"NestedPassword\x00"]
    monkeypatch.setattr(code, "decrypt_blob", decrypt)
    observation = {}
    if scenario in ("plain", "nested"):
        result = code.recover_eap_credentials(triage, "profile", observation)
        assert result["username"] == b"alice"
        assert result["domain"] == b"EXAMPLE"
        assert result["password"] == (b"NestedPassword" if scenario == "nested" else b"password")
        assert observation["status"] == "recovered"
    else:
        with pytest.raises((ValueError, RuntimeError, PermissionError)):
            code.recover_eap_credentials(triage, "profile", observation)
        assert observation["status"] == ("inconclusive" if scenario == "absent" else "failed")
        assert observation["error"]
        if scenario in ("nested_key", "truncated"):
            assert observation["credentials"]["username"] == b"alice"
            assert observation["credentials"]["password"] is None
    assert observation["attempts"]
    if scenario == "denied":
        assert observation["attempts"][0]["error"] == "denied"
