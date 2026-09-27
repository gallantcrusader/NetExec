"""Offline permission records retain grantees, grantors, targets, and states."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules.enum_impersonate import NXCModule
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize(("state", "target", "permission"), [("GRANT", "target", "IMPERSONATE"), ("DENY", "target", "IMPERSONATE"), ("GRANT_WITH_GRANT_OPTION", None, "IMPERSONATE ANY LOGIN")])
def test_permission_identity_and_scope_are_retained(state, target, permission):
    row = {"grantee": "recipient", "grantor": "administrator", "target_login": target, "state_desc": state, "permission_name": permission, "major_id": 0 if target is None else 7}
    conn = SimpleNamespace(lastError=None, sql_query=Mock(return_value=[row]))
    module = NXCModule()
    result = module.on_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=conn, host="offline.invalid"))
    validate_module_result(module, result, "mssql", "offline.invalid")
    assert result.status is ResultStatus.SUCCESS
    assert result.data.permissions == [row]
    sql = conn.sql_query.call_args.args[0]
    assert "p.grantee_principal_id = grantee.principal_id" in sql
    assert "p.class = 101 AND p.major_id = target.principal_id" in sql
    assert "p.state_desc" in sql


@pytest.mark.parametrize("raises", [False, True])
def test_permission_query_failure_is_not_empty_success(raises):
    conn = SimpleNamespace(lastError="query denied", sql_query=Mock(return_value=[]))
    if raises:
        conn.sql_query.side_effect = RuntimeError("query denied")
    result = NXCModule().on_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=conn, host="offline.invalid"))
    assert result.status is ResultStatus.FAILED
    assert result.error == "query denied"


def test_empty_permissions_are_negative():
    conn = SimpleNamespace(lastError=None, sql_query=Mock(return_value=[]))
    result = NXCModule().on_login(SimpleNamespace(log=Mock()), SimpleNamespace(conn=conn, host="offline.invalid"))
    assert result.status is ResultStatus.NEGATIVE
