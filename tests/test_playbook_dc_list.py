"""Domain controller results with mocked LDAP and DNS."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


def dc_entry(**attrs):
    entry = SearchResultEntry()
    entry["objectName"] = "DC=example,DC=test"
    for index, (key, value) in enumerate(attrs.items()):
        entry["attributes"][index]["type"] = key
        entry["attributes"][index]["vals"][0] = value
    return entry


@pytest.mark.parametrize("failure", [None, "ldap", "dns", "srv"])
def test_dc_list_keeps_controller_domains_and_partial_data(monkeypatch, failure):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    fake = SimpleNamespace(host="192.0.2.1", domain="example.test", args=SimpleNamespace(dns_server=None, dns_timeout=3, dns_tcp=False), logger=Mock(), playbook_mode=True)
    calls = []
    trust = {"name": "other.test", "flatName": "OTHER", "trustDirection": "3", "trustType": "2", "trustAttributes": "32"}

    def search(*args):
        calls.append(args)
        fake.last_search_error = "partial LDAP failure" if failure == "ldap" and len(calls) == 1 else None
        return [dc_entry(dNSHostName="dc.example.test")] if len(calls) == 1 else [dc_entry(**trust)]

    def resolve(name, record_type, tcp):
        if record_type == "SRV":
            if failure == "srv":
                raise protocol.resolver.Timeout
            return [SimpleNamespace(target="dc.other.test.")]
        if failure == "dns":
            raise protocol.resolver.NXDOMAIN
        return [SimpleNamespace(to_text=lambda: "192.0.2.2")]

    fake.search = search
    monkeypatch.setattr(protocol.resolver, "Resolver", lambda **kwargs: SimpleNamespace(resolve=resolve))
    monkeypatch.setattr(protocol.socket, "gethostbyname", lambda value: "192.0.2.1")
    result = protocol.ldap.dc_list(fake)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.trusts == [trust]
    assert result.data.controllers[0]["domain"] == "example.test"
    if failure != "srv":
        assert result.data.controllers[1]["domain"] == "other.test"
    assert result.data.controllers[0]["value"] == (None if failure == "dns" else "192.0.2.2")
    if failure == "ldap":
        assert result.error == "partial LDAP failure"
    assert result.to_dict()["data"]["controllers"][0]["hostname"] == "dc.example.test"


def test_empty_dc_list_is_negative_and_does_not_query_dns(monkeypatch):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    dns = Mock()
    monkeypatch.setattr(protocol.resolver, "Resolver", lambda **kwargs: dns)
    monkeypatch.setattr(protocol.socket, "gethostbyname", lambda value: "192.0.2.1")
    fake = SimpleNamespace(host="192.0.2.1", domain="example.test", args=SimpleNamespace(dns_server=None, dns_timeout=3, dns_tcp=False), logger=Mock(), playbook_mode=True, search=Mock(return_value=[]), last_search_error=None)
    result = protocol.ldap.dc_list(fake)
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.controllers == []
    assert result.data.trusts == []
    dns.resolve.assert_not_called()
