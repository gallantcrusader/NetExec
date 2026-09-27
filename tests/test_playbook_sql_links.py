"""Offline linked-server queries preserve mappings and database failures."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules.enum_links import NXCModule
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("admin", [False, True])
def test_links_preserve_raw_metadata_and_unnamed_login(admin):
    module = NXCModule()
    context = SimpleNamespace(log=Mock())
    server = {"SRV_NAME": "REPORTS", "SRV_PROVIDERNAME": "SQLNCLI", "SRV_DATASOURCE": "sql.example.test"}
    mapping = {"Linked Server": "REPORTS", "Local Login": None, "Is Self Mapping": 1, "Remote Login": None}
    conn = SimpleNamespace(lastError=None, sql_query=Mock(side_effect=[[server], [mapping]]))
    connection = SimpleNamespace(conn=conn, host="offline.invalid", admin_privs=admin)
    result = module.on_login(context, connection)
    validate_module_result(module, result, "mssql", connection.host)
    assert result.status is ResultStatus.SUCCESS
    assert result.data.servers == [server]
    assert result.data.login_mappings == ([mapping] if admin else [])
    assert result.data.login_mappings_queried is admin
    assert conn.sql_query.call_count == (2 if admin else 1)


@pytest.mark.parametrize("stage", [1, 2])
@pytest.mark.parametrize("raises", [False, True])
def test_link_failures_keep_prior_data(stage, raises):
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
        return [{"SRV_NAME": "REPORTS"}]

    conn.sql_query = query
    result = NXCModule().on_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=conn, host="offline.invalid", admin_privs=True))
    assert result.status is ResultStatus.FAILED
    assert result.error == "query denied"
    assert result.data.servers == ([] if stage == 1 else [{"SRV_NAME": "REPORTS"}])
    assert len(calls) == stage
    assert result.data.login_mappings_queried is (stage == 2)


def test_no_links_is_negative():
    connection = SimpleNamespace(host="offline.invalid", admin_privs=True, conn=SimpleNamespace(lastError=None, sql_query=Mock(return_value=[])))
    result = NXCModule().on_login(SimpleNamespace(log=Mock()), connection)
    assert result.status is ResultStatus.NEGATIVE
    assert result.data.login_mappings_queried
