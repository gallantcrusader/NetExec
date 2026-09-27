"""Offline DNS zone/record results, partial queries and export failures."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import nxc.modules.enum_dns as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("protocol", ["smb", "wmi"])
@pytest.mark.parametrize("failure", [None, "zones", "records", "file"])
def test_dns_records_preserve_wmi_data(monkeypatch, tmp_path, protocol, failure):
    root = tmp_path / "output"
    if failure == "file":
        root.write_text("file")
    monkeypatch.setattr(code, "NXC_PATH", root)
    properties = {"TextRepresentation": {"value": 'host.example. 300 IN TXT "a  b"'}, "TTL": {"value": 300}, "RecordData": {"value": ["a  b", "é"]}}
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol=protocol), last_wmi_error=None)

    def query(statement, namespace):
        assert namespace == "root\\microsoftdns"
        if "MicrosoftDNS_Zone" in statement:
            conn.last_wmi_error = "partial zones" if failure == "zones" else None
            return [{"Name": {"value": zone}} for zone in ["example", "example", "second"]]
        conn.last_wmi_error = "partial records" if failure == "records" else None
        return [properties] if "'example'" in statement else []

    conn.wmi_query = Mock(side_effect=query)
    module = code.NXCModule()
    result = module.on_admin_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, protocol, conn.host)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.zones == ["example", "second"]
    if failure == "zones":
        assert result.data.records == []
        assert result.data.queried_zones == []
        assert conn.wmi_query.call_count == 1
    else:
        assert result.data.records == [{"zone": "example", "text": properties["TextRepresentation"]["value"], "properties": properties}]
        assert result.data.queried_zones == (["example"] if failure == "records" else ["example", "second"])
    if failure == "file":
        assert not result.artifacts
    else:
        text = result.artifacts[0].path.read_text(encoding="utf-8")
        if failure != "zones":
            assert properties["TextRepresentation"]["value"] in text


def test_explicit_dns_zone_is_literal_and_empty_is_negative(monkeypatch, tmp_path):
    monkeypatch.setattr(code, "NXC_PATH", tmp_path)
    conn = SimpleNamespace(host="offline.invalid", args=SimpleNamespace(protocol="smb"), last_wmi_error=None, wmi_query=Mock(return_value=[]))
    module = code.NXCModule()
    module.options(None, {"DOMAIN": "quote'\\zone"})
    result = module.on_admin_login(SimpleNamespace(log=Mock()), conn)
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.zones == ["quote'\\zone"]
    conn.wmi_query.assert_called_once_with("Select * FROM MicrosoftDNS_ResourceRecord WHERE DomainName = 'quote\\'\\\\zone'", "root\\microsoftdns")
