"""Playbook ergonomics: session.authenticated/credential/admin, result.rows/one(),
host.defaults() with per-call priority, result.index + host.evidence(), host.finding(),
and the ModuleResult container.
"""

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from nxc.playbooks.results import ActionResult, CredentialRef, ModuleResult, ResultStatus, tabular_rows
from nxc.playbooks.runner import ConnectionData, FailureData, HostContext, PlaybookStepError, ProtocolSession, VerdictData, _UNSET


@dataclass
class ColumnsRows:
    columns: list
    rows: list


@dataclass
class Entries:
    attributes: list
    entries: list


@dataclass
class Records:
    records: list


def make_session(host, data, *, protocol="smb", unusable=None):
    connection = SimpleNamespace(playbook_unusable_reason=unusable)
    result = ActionResult(protocol, "connect", host.target, ResultStatus.SUCCESS if data is not None else ResultStatus.FAILED, data)
    return ProtocolSession(host, protocol, connection, SimpleNamespace(), None, None, result)


# --- session convenience -----------------------------------------------------

def test_session_authenticated_true_for_real_login():
    host = HostContext("t", [])
    session = make_session(host, ConnectionData(connected=True, authenticated=True, anonymous=False))
    assert session.authenticated is True


def test_session_authenticated_false_for_anonymous_or_guest():
    host = HostContext("t", [])
    anon = make_session(host, ConnectionData(connected=True, authenticated=False, anonymous=True))
    guest = make_session(host, ConnectionData(connected=True, authenticated=False, anonymous=False, guest=True))
    assert anon.authenticated is False
    assert guest.authenticated is False


def test_session_authenticated_false_and_safe_for_failure_data():
    host = HostContext("t", [])
    session = make_session(host, FailureData("boom"))
    session.result.status = ResultStatus.FAILED
    # Must not raise even though .data is not ConnectionData.
    assert session.authenticated is False
    assert session.credential is None
    assert session.admin is None


def test_session_credential_and_admin_shortcuts():
    host = HostContext("t", [])
    ref = CredentialRef("smb", 7)
    session = make_session(host, ConnectionData(connected=True, authenticated=True, anonymous=False, credential=ref, admin_privileges=True))
    assert session.credential == ref
    assert session.admin is True


# --- tabular rows / one() ----------------------------------------------------

def test_tabular_rows_from_columns_and_rows_tuples():
    data = ColumnsRows(columns=["a", "b"], rows=[(1, 2), (3, 4)])
    assert tabular_rows(data) == [{"a": 1, "b": 2}, {"a": 3, "b": 4}]


def test_tabular_rows_duplicate_columns_last_wins():
    data = ColumnsRows(columns=["x", "x", "y"], rows=[(1, 2, 3)])
    assert tabular_rows(data) == [{"x": 2, "y": 3}]


def test_tabular_rows_from_entries_and_records():
    assert tabular_rows(Entries(attributes=["a"], entries=[{"a": 1}])) == [{"a": 1}]
    assert tabular_rows(Records(records=[{"a": 1}, {"a": 2}])) == [{"a": 1}, {"a": 2}]


def test_tabular_rows_rejects_non_tabular():
    with pytest.raises(TypeError, match="no tabular rows"):
        tabular_rows(SimpleNamespace(nope=1))


def test_result_rows_and_one():
    result = ActionResult("mssql", "query", "t", ResultStatus.SUCCESS, ColumnsRows(columns=["n"], rows=[(5,)]))
    assert result.rows == [{"n": 5}]
    assert result.one() == {"n": 5}


def test_result_one_raises_when_not_exactly_one_row():
    result = ActionResult("mssql", "query", "t", ResultStatus.SUCCESS, ColumnsRows(columns=["n"], rows=[(1,), (2,)]))
    with pytest.raises(ValueError, match="expected exactly one"):
        result.one()


# --- stop_on_error defaults with per-call priority ---------------------------

def failed_result(target):
    return ActionResult("smb", "step", target, ResultStatus.FAILED, FailureData("nope"), error="nope")


def test_record_raises_by_default():
    host = HostContext("t", [])
    with pytest.raises(PlaybookStepError):
        host.record(failed_result(host.target))


def test_defaults_stop_on_error_false_suppresses_raise():
    host = HostContext("t", [])
    host.defaults(stop_on_error=False)
    recorded = host.record(failed_result(host.target))
    assert recorded.status is ResultStatus.FAILED  # no raise


def test_explicit_stop_on_error_overrides_default():
    host = HostContext("t", [])
    host.defaults(stop_on_error=False)
    with pytest.raises(PlaybookStepError):
        host.record(failed_result(host.target), stop_on_error=True)


def test_session_stop_resolution_prefers_explicit():
    host = HostContext("t", [])
    session = make_session(host, ConnectionData(True, True, False))
    assert session._stop(_UNSET) is True  # workflow default
    host.defaults(stop_on_error=False)
    assert session._stop(_UNSET) is False  # falls back to workflow default
    assert session._stop(True) is True  # explicit wins


def test_defaults_do_not_pollute_connection_defaults():
    host = HostContext("t", [], {"domain": "corp"})
    host.defaults(stop_on_error=False)
    assert host.connection_defaults == {"domain": "corp"}


# --- result.index + evidence -------------------------------------------------

def test_record_assigns_sequential_index():
    host = HostContext("t", [])
    host.defaults(stop_on_error=False)
    a = host.record(failed_result(host.target))
    b = host.record(failed_result(host.target))
    assert a.index == 0
    assert b.index == 1


def test_evidence_collects_indices_recorded_in_block():
    host = HostContext("t", [])
    host.defaults(stop_on_error=False)
    host.record(failed_result(host.target))  # index 0, outside the block
    with host.evidence() as ev:
        host.record(failed_result(host.target))  # index 1
        host.record(failed_result(host.target))  # index 2
    host.record(failed_result(host.target))  # index 3, after the block
    assert ev.indices == [1, 2]


# --- host.finding() ----------------------------------------------------------

def test_finding_ok_records_success_verdict():
    host = HostContext("t", [])
    result = host.finding("my_check", ok=True, inputs={"x": 1})
    assert result.status is ResultStatus.SUCCESS
    assert isinstance(result.data, VerdictData)
    assert result.data.ok is True
    assert result.inputs == {"x": 1}
    assert host.run.results[-1] is result


def test_finding_not_ok_records_negative_and_keeps_custom_data():
    host = HostContext("t", [])

    @dataclass
    class Evidence:
        reached: bool

    result = host.finding("path", ok=False, data=Evidence(reached=False))
    assert result.status is ResultStatus.NEGATIVE
    assert result.data == Evidence(reached=False)


# --- ModuleResult container --------------------------------------------------

def one_result(status=ResultStatus.SUCCESS, data=None):
    return ActionResult("smb", "mod", "t", status, data if data is not None else ColumnsRows(["n"], [(1,)]))


def test_module_result_single_proxies_attributes():
    inner = one_result()
    mr = ModuleResult([inner])
    assert mr.ok is True
    assert mr.status is ResultStatus.SUCCESS
    assert mr.data is inner.data
    assert mr.rows == [{"n": 1}]
    assert mr.one() == {"n": 1}
    assert mr.first is inner
    assert len(mr) == 1
    assert list(mr) == [inner]


def test_module_result_multi_iterates_and_aggregates():
    ok = one_result()
    bad = one_result(status=ResultStatus.FAILED)
    bad.error = "explode"
    mr = ModuleResult([ok, bad])
    assert len(mr) == 2
    assert [r.status for r in mr] == [ResultStatus.SUCCESS, ResultStatus.FAILED]
    assert mr.ok is False  # not all ok
    assert mr.error == "explode"  # first failure surfaced


def test_module_result_single_only_attrs_raise_on_multi():
    mr = ModuleResult([one_result(), one_result()])
    with pytest.raises(ValueError, match="iterate the results"):
        _ = mr.status


def test_module_result_empty_is_falsey():
    mr = ModuleResult([])
    assert bool(mr) is False
    assert mr.ok is False
