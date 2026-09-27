"""Offline INF parsing and policy privilege records."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules.gpp_privileges import NXCModule
from nxc.playbooks.results import CredentialRef, ResultStatus


def test_privilege_section_handles_blank_lines_and_boundaries():
    content = "\ufeff[Privilege Rights]\n SeFirst = *S-1-5-18, *S-1-5-32-544\n\n; comment\nSeEmpty=\n[Other]\nNotPrivilege=value\n"
    assert NXCModule().extract_privileges(content) == {"SeFirst": ["S-1-5-18", "S-1-5-32-544"], "SeEmpty": []}


@pytest.mark.parametrize("value", ["false", "true"])
def test_no_ldap_option_parses_boolean(value):
    module = NXCModule()
    module.options(SimpleNamespace(log=Mock()), {"NO_LDAP": value})
    assert module.no_ldap is (value == "true")


def test_policy_records_keep_partial_file_errors():
    module = NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {"NO_LDAP": "true"})
    conn = Mock()

    def get_file(share, path, write):
        if path == "bad":
            raise RuntimeError("read denied")
        write("[Privilege Rights]\nSeBackupPrivilege = *S-1-5-18, *S-1-5-21-999".encode("utf-16le"))

    conn.getFile.side_effect = get_file
    connection = SimpleNamespace(host="offline.invalid", conn=conn, spider=Mock(return_value=["good", "bad"]))
    result = module.on_login(context, connection)
    assert result.status is ResultStatus.FAILED
    assert result.data.policies[0]["privileges"] == [{"privilege": "SeBackupPrivilege", "principals": [{"sid": "S-1-5-18", "name": "Local System"}, {"sid": "S-1-5-21-999", "name": None}]}]
    assert result.data.policies[1]["error"] == "read denied"
    assert not result.data.ldap_resolution_requested


def test_policy_resolution_reuses_one_ldap_connection(monkeypatch):
    module = NXCModule()
    context = SimpleNamespace(log=Mock())
    module.options(context, {})
    ldap = Mock()
    ldap.close.side_effect = RuntimeError("cleanup denied")
    ldap.search.return_value = []
    initialize = Mock(return_value=ldap)
    monkeypatch.setattr(module, "initialize_ldap_connection", initialize)
    monkeypatch.setattr(module, "get_basedn", Mock(return_value="DC=example,DC=test"))
    conn = Mock()
    conn.getFile.side_effect = lambda share, path, write: write("[Privilege Rights]\nSeBackupPrivilege=*S-1-5-21-999".encode("utf-16le"))
    result = module.on_login(context, SimpleNamespace(host="offline.invalid", conn=conn, spider=Mock(return_value=["first", "second"])))
    assert result.status is ResultStatus.FAILED
    assert len(result.data.policies) == 2
    assert "cleanup denied" in result.error
    initialize.assert_called_once()
    ldap.close.assert_called_once_with()


@pytest.mark.parametrize("failure", [None, "connect", "query", "credential"])
def test_playbook_policy_resolution_uses_shared_session_and_reference(monkeypatch, failure):
    module = NXCModule()
    credential = CredentialRef("smb", 5)
    shared = SimpleNamespace(ok=failure != "connect", result=SimpleNamespace(error="connect denied"), query=Mock(return_value=SimpleNamespace(error="query denied" if failure == "query" else None, data=SimpleNamespace(entries=[{"sAMAccountName": "Alice"}]))), close=Mock())
    host = SimpleNamespace(ldap=Mock(return_value=shared))
    context = SimpleNamespace(log=Mock(), playbook=host, credential=None if failure == "credential" else credential)
    module.options(context, {})
    fresh_connection = Mock()
    monkeypatch.setattr(module, "initialize_ldap_connection", fresh_connection)
    conn = Mock()
    conn.getFile.side_effect = lambda share, path, write: write("[Privilege Rights]\nSeBackupPrivilege=*S-1-5-21-999".encode("utf-16le"))
    result = module.on_login(context, SimpleNamespace(host="offline.invalid", conn=conn, spider=Mock(return_value=["policy"])))
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    fresh_connection.assert_not_called()
    shared.close.assert_not_called()
    if failure == "credential":
        host.ldap.assert_not_called()
    else:
        host.ldap.assert_called_once_with(credential=credential, anonymous=False, stop_on_error=False)
    principal = result.data.policies[0]["privileges"][0]["principals"][0]
    assert principal["sid"] == "S-1-5-21-999"
    assert principal["name"] == (None if failure in ("connect", "credential") else "Alice")


def test_well_known_policy_sids_need_no_ldap_session():
    module = NXCModule()
    context = SimpleNamespace(log=Mock(), playbook=SimpleNamespace(ldap=Mock()), credential=None)
    module.options(context, {})
    conn = Mock()
    conn.getFile.side_effect = lambda share, path, write: write("[Privilege Rights]\nSeBackupPrivilege=*S-1-5-18".encode("utf-16le"))
    result = module.on_login(context, SimpleNamespace(host="offline.invalid", conn=conn, spider=Mock(return_value=["policy"])))
    assert result.status is ResultStatus.SUCCESS
    context.playbook.ldap.assert_not_called()
