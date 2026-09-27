"""Offline SQL search preserves schemas, raw values and partial errors."""

from decimal import Decimal
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.modules import mssql_dumper as code
from nxc.playbooks.contracts import validate_module_result
from nxc.playbooks.results import ResultStatus


@pytest.mark.parametrize("scenario", ["normal", "partial", "metadata", "export", "empty", "no_save"])
def test_sql_inventory(monkeypatch, tmp_path, scenario):
    root = tmp_path / "output"
    if scenario == "export":
        root.write_text("file")
    monkeypatch.setattr(code, "NXC_PATH", root)
    module = code.NXCModule()
    module.options(SimpleNamespace(log=Mock()), {"LIKE_SEARCH": "password", "USE_PRESET": False, "SHOW_DATA": False, "SAVE": scenario != "no_save", "REGEX": "^  |None"})
    raw = {"password]": b"  Value\xff  ", "null": None, "amount": Decimal("1.20")}
    sql = SimpleNamespace(lastError=False)
    calls = []

    def query(statement):
        calls.append(statement)
        sql.lastError = False
        assert not statement.startswith("USE ")
        if statement == "SELECT name FROM master.dbo.sysdatabases":
            return [{"name": "master"}, {"name": "data]base"}]
        if ".INFORMATION_SCHEMA.TABLES" in statement:
            if scenario == "metadata":
                sql.lastError = "table listing failed"
            return [] if scenario == "empty" else [{"table_schema": "custom'", "table_name": "table]name"}]
        if ".INFORMATION_SCHEMA.COLUMNS" in statement:
            assert "TABLE_SCHEMA = 'custom'''" in statement
            assert "TABLE_NAME = 'table]name'" in statement
            return [{"column_name": name} for name in raw]
        if statement.startswith("SELECT [password]]]"):
            assert statement.endswith("FROM [data]]base].[custom'].[table]]name]")
            if scenario == "partial":
                sql.lastError = "partial data"
            return [{"password]": raw["password]"]}]
        if statement.startswith("SELECT *"):
            return [raw]
        pytest.fail(statement)

    sql.sql_query = Mock(side_effect=query)
    conn = SimpleNamespace(host="offline.invalid", conn=sql)
    result = module.on_login(SimpleNamespace(log=Mock()), conn)
    validate_module_result(module, result, "mssql", conn.host)
    assert result.status is (ResultStatus.FAILED if scenario in ("partial", "metadata", "export") else ResultStatus.NEGATIVE if scenario == "empty" else ResultStatus.SUCCESS)
    if scenario in ("metadata", "empty"):
        assert not result.data.matches
    else:
        assert result.data.matches[0]["schema"] == "custom'"
        assert result.data.matches[0]["row"]["password]"] == raw["password]"]
        if scenario != "partial":
            assert result.data.matches[1]["matched_cells"] == {"password]": raw["password]"], "null": None}
    if scenario == "partial":
        assert len(calls) == 4
        assert result.data.queries[-1]["error"] == "partial data"
    if scenario in ("normal", "partial"):
        saved = json.loads(result.artifacts[0].path.read_text())
        assert saved[0]["row"]["password]"]
    elif scenario == "no_save":
        assert result.artifacts == []


def test_invalid_regex_stops_before_search():
    with pytest.raises(SystemExit):
        code.NXCModule().options(SimpleNamespace(log=Mock()), {"REGEX": "["})
