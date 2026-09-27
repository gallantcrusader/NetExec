"""Offline MSSQL rows, errors, and retry behavior."""

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("error", [None, "SQL error"])
def test_sql_query_preserves_duplicate_columns_values_and_errors(error):
    protocol = ProtocolLoader().load_protocol("nxc/protocols/mssql.py")
    conn = SimpleNamespace(lastError="previous SQL error", colMeta=[])
    rows = [(Decimal("1234567890.123456789"), b"\x00\xff", None)]

    def query(statement, tuplemode):
        assert tuplemode is True
        conn.lastError = error
        conn.colMeta = [{"Name": "same"}, {"Name": "same"}, {"Name": "nullable"}]
        return rows

    conn.sql_query = Mock(side_effect=query)
    fake = SimpleNamespace(conn=conn, args=SimpleNamespace(query="SELECT example"), playbook_mode=True, host="offline.invalid", logger=Mock())
    result = protocol.mssql.query(fake)
    assert result.status is (ResultStatus.FAILED if error else ResultStatus.SUCCESS)
    assert result.data.columns == ["same", "same", "nullable"]
    assert result.data.rows == rows
    assert result.error == error
    encoded = result.to_dict()["data"]["rows"][0]
    assert encoded[0] == "1234567890.123456789"
    assert encoded[1] == {"encoding": "base64", "value": "AP8="}
    assert encoded[2] is None
    rows.clear()
    assert len(result.data.rows) == 1


def test_sql_no_rows_is_success():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/mssql.py")
    fake = SimpleNamespace(conn=SimpleNamespace(lastError=None, colMeta=[], sql_query=Mock(return_value=[])), args=SimpleNamespace(query="SELECT example WHERE 1=0"), playbook_mode=True, host="offline.invalid", logger=Mock())
    result = protocol.mssql.query(fake)
    assert result.status is ResultStatus.SUCCESS
    assert result.data.rows == []


def test_sql_transport_failure_is_structured():
    protocol = ProtocolLoader().load_protocol("nxc/protocols/mssql.py")
    fake = SimpleNamespace(conn=SimpleNamespace(lastError=None, colMeta=[], sql_query=Mock(side_effect=OSError("connection lost"))), args=SimpleNamespace(query="SELECT example"), playbook_mode=True, host="offline.invalid", logger=Mock())
    result = protocol.mssql.query(fake)
    assert result.status is ResultStatus.FAILED
    assert result.error == "connection lost"
