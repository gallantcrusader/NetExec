"""Offline computer inventory records and output failures."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


def computer_entry(**attrs):
    entry = SearchResultEntry()
    entry["objectName"] = "CN=Computer,DC=example,DC=test"
    for i, (key, value) in enumerate(attrs.items()):
        entry["attributes"][i]["type"] = key
        entry["attributes"][i]["vals"][0] = value
    return entry


@pytest.mark.parametrize(("mode", "line"), [("netbios", "server"), ("fqdn", "server.example.test"), ("", "server.example.test (Unknown OS)")])
def test_computer_records_independent_of_display_mode(mode, line, tmp_path):
    module = import_module("nxc.modules.dump-computers").NXCModule()
    context = SimpleNamespace(log=Mock())
    output = tmp_path / "computers.txt"
    module.options(context, {"TYPE": mode, "OUTPUT": str(output)})
    connection = SimpleNamespace(host="offline.invalid", last_search_error=None, search=Mock(return_value=[computer_entry(dNSHostName="server.example.test"), computer_entry(cn="missing-dns")]))
    result = module.on_login(context, connection)
    validate_module_result(module, result, "ldap", connection.host)
    assert result.status is ResultStatus.SUCCESS
    assert result.data.computers == [{"dns_hostname": "server.example.test", "operating_system": None, "dns_short_name": "server"}]
    assert result.data.output_lines == [line]
    assert output.read_text() == line + "\n"
    assert result.artifacts[0].path == output


@pytest.mark.parametrize("partial", [False, True])
def test_search_and_file_errors_are_preserved(tmp_path, partial):
    module = import_module("nxc.modules.dump-computers").NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"OUTPUT": str(tmp_path / "missing" / "computers.txt")})
    connection = SimpleNamespace(host="offline.invalid", last_search_error="partial search" if partial else None, search=Mock(return_value=[computer_entry(dNSHostName="server.example.test", operatingSystem="Windows")]))
    result = module.on_login(context, connection)
    assert result.status is ResultStatus.FAILED
    assert result.data.computers[0]["operating_system"] == "Windows"
    assert result.artifacts == []
    if partial:
        assert result.error.startswith("partial search; ")
    assert "computers.txt" in result.error
