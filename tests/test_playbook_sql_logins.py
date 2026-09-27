"""Offline SQL login metadata, classification, and failures."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules.enum_logins import NXCModule
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus, json_value


@pytest.mark.parametrize(("name", "kind", "domain", "expected"), [
    ("EXAMPLE\\Alice", "WINDOWS_LOGIN", "example", "Domain User"),
    ("TRUSTED\\Bob", "WINDOWS_LOGIN", "example", "Windows User"),
    ("EXAMPLE\\Alice", "WINDOWS_LOGIN", None, "Windows User"),
    ("sa", "SQL_LOGIN", None, "SQL User"),
    ("Group", "WINDOWS_GROUP", "example", "Windows Group"),
])
def test_login_metadata_and_domain_classification(name, kind, domain, expected):
    row = {"name": name, "type_desc": kind, "type": "U", "is_disabled": 1, "create_date": datetime(2026, 1, 1)}
    conn = SimpleNamespace(lastError=None, sql_query=Mock(side_effect=[[{"domain_name": domain}], [row]]))
    module = NXCModule()
    result = module.on_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=conn, host="offline.invalid"))
    validate_module_result(module, result, "mssql", "offline.invalid")
    assert result.status is ResultStatus.SUCCESS
    assert result.data.default_domain == domain
    assert result.data.logins == [{**row, "login_type": expected}]
    assert "login_type" not in row
    assert json_value(result.data)["logins"][0]["create_date"] == "2026-01-01T00:00:00"


@pytest.mark.parametrize("stage", [1, 2])
@pytest.mark.parametrize("raises", [True, False])
def test_query_failure_preserves_collected_results(stage, raises):
    conn = SimpleNamespace(lastError=None)
    calls = []

    def query(sql):
        calls.append(sql)
        conn.lastError = None
        if len(calls) == stage:
            if raises:
                raise RuntimeError("query denied")
            conn.lastError = "query denied"
            return []
        return [{"domain_name": "EXAMPLE"}] if len(calls) == 1 else [{"name": "sa", "type_desc": "SQL_LOGIN"}]

    conn.sql_query = query
    result = NXCModule().on_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=conn, host="offline.invalid"))
    assert result.status is ResultStatus.FAILED
    assert result.error == "query denied"
    assert len(result.data.logins) == (1 if stage == 1 else 0)
    assert result.data.default_domain == (None if stage == 1 else "EXAMPLE")


def test_empty_logins_is_negative():
    conn = SimpleNamespace(lastError=None, sql_query=Mock(return_value=[]))
    result = NXCModule().on_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=conn, host="offline.invalid"))
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.logins == []
