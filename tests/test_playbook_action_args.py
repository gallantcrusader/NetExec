"""Use protocol CLI arity for Python action options without connecting."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.cli import gen_cli_args
from nxc.playbooks.results import ActionResult, ResultStatus
from nxc.playbooks.runner import ConnectionData, HostContext, ProtocolSession, normalize_action_option


@pytest.mark.parametrize(("action", "value", "expected", "failed"), [
    ("users", "alice", ["alice"], False),
    ("users", ("alice", "bob"), ["alice", "bob"], False),
    ("users", None, [], False),
    ("query", ("(objectClass=user)", "name"), ["(objectClass=user)", "name"], False),
    ("query", "(objectClass=user)", None, True),
    ("query", [], None, True),
    ("groups", "Domain Users", "Domain Users", False),
])
def test_action_argument_normalization_and_restoration(action, value, expected, failed):
    args, _, parser = gen_cli_args(["ldap", "offline.invalid"], with_parser=True)
    original = getattr(args, action)
    method = Mock(side_effect=lambda: {"received": getattr(args, action)})
    method.requires_admin = False
    fake = SimpleNamespace(host="offline.invalid", logger=Mock(), **{action: method})
    host = HostContext(fake.host, [])
    connected = ActionResult("ldap", "connect", fake.host, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "ldap", fake, args, None, None, connected, {item.dest: item.nargs for item in parser._actions})
    result = session.action(action, stop_on_error=False, **{action: value})
    assert result.status is (ResultStatus.FAILED if failed else ResultStatus.SUCCESS)
    assert getattr(args, action) == original
    assert result.inputs == {action: value}
    if failed:
        method.assert_not_called()
        assert "requires 2 values" in result.error
    else:
        assert result.data.return_value == {"received": expected}


@pytest.mark.parametrize("value", [("source", "destination"), [("source", "destination")], [("a", "b"), ("c", "d"), ("e", "f")]])
def test_repeated_transfer_pairs_are_normalized(value):
    expected = [["source", "destination"]] if len(value) != 3 else [["a", "b"], ["c", "d"], ["e", "f"]]
    assert normalize_action_option("get_file", value, 2, append=True) == expected


def test_incomplete_repeated_pair_is_rejected():
    with pytest.raises(ValueError, match="requires 2 values"):
        normalize_action_option("get_file", [("source", "destination"), ("missing",)], 2, append=True)
