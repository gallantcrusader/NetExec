"""Offline binary LDAP DNS records and export selection."""

from importlib import import_module
from struct import pack
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def dns_record(type_id, data):
    return pack("<HHBBHL", len(data), type_id, 5, 240, 0, 7) + pack(">L", 300) + pack("<LL", 0, 99) + data


def node(name, records, tombstoned=False):
    entry = SearchResultEntry()
    entry["objectName"] = f"DC={name},DC=example.test"
    attrs = {"name": [name], "dnsRecord": records, "dNSTombstoned": ["TRUE" if tombstoned else "FALSE"]}
    for index, (key, values) in enumerate(attrs.items()):
        entry["attributes"][index]["type"] = key
        for offset, value in enumerate(values):
            entry["attributes"][index]["vals"][offset] = value
    return entry


@pytest.mark.parametrize("options", [{}, {"ALL": True}, {"ONLY_HOSTS": "true"}])
def test_full_inventory_is_independent_of_export_options(monkeypatch, tmp_path, options):
    code = import_module("nxc.modules.get-network")
    monkeypatch.setattr(code, "NXC_PATH", tmp_path)
    module = code.NXCModule()
    module.options(None, options)
    a = dns_record(1, bytes([192, 0, 2, 1]))
    aaaa = dns_record(28, bytes.fromhex("20010db8000000000000000000000001"))
    cname = dns_record(5, b"\x0e\x02\x07example\x04test")
    unknown = dns_record(65000, b"opaque")
    entries = [node("@", [a, aaaa]), node("duplicate", [a]), node("alias", [cname]), node("other", [unknown]), node("old", [a], True)]
    conn = SimpleNamespace(host="offline.invalid", baseDN="DC=example,DC=test", last_search_error=None, search=Mock(return_value=entries))
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "ldap", conn.host)
    assert result.status is ResultStatus.SUCCESS
    assert len(result.data.records) == 6
    assert result.data.records[0]["fqdn"] == "example.test"
    assert result.data.records[0]["ttl"] == 300
    assert result.data.records[0]["serial"] == 7
    assert result.data.records[0]["raw"] == a
    assert result.data.records[1]["value"] == "2001:db8::1"
    assert result.data.records[3]["value"] == "example.test."
    assert result.data.records[4]["type"] is None
    assert result.data.records[4]["type_id"] == 65000
    assert result.data.records[4]["raw"] == unknown
    assert result.data.records[5]["tombstoned"]
    if not options:
        assert result.data.export_lines == ["192.0.2.1", "2001:db8::1"]
    elif "ALL" in options:
        assert result.data.export_lines == ["example.test \t 192.0.2.1", "example.test \t 2001:db8::1", "duplicate.example.test \t 192.0.2.1", "alias.example.test \t example.test."]
    else:
        assert result.data.export_lines == ["example.test", "example.test", "duplicate.example.test", "alias.example.test"]
    assert result.artifacts[0].path.read_text().splitlines() == result.data.export_lines
    assert result.data.search_base == "DC=example.test,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=test"
    assert result.to_dict()["data"]["records"][0]["raw"]


@pytest.mark.parametrize("failure", ["search", "export", None])
def test_empty_or_failed_inventory(monkeypatch, tmp_path, failure):
    code = import_module("nxc.modules.get-network")
    root = tmp_path / "output"
    if failure == "export":
        root.write_text("file")
    monkeypatch.setattr(code, "NXC_PATH", root)
    module = code.NXCModule()
    module.options(None, {})
    entries = [node("host", [dns_record(1, bytes([192, 0, 2, 1]))])] if failure else []
    conn = SimpleNamespace(host="offline.invalid", baseDN="DC=example,DC=test", last_search_error="partial query" if failure == "search" else None, search=Mock(return_value=entries))
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.NEGATIVE)
    assert len(result.data.records) == (1 if failure else 0)
    assert bool(result.error) == bool(failure)
    assert bool(result.artifacts) == (failure != "export")


def test_dns_binary_values_are_never_decoded_as_utf8():
    # Even a blob consisting entirely of valid UTF-8 bytes remains binary.
    entry = node("host", [b"ascii bytes", b"\x00\x01"])
    assert parse_result_attributes([entry])[0]["dnsRecord"] == [b"ascii bytes", b"\x00\x01"]
