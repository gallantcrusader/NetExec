"""Group changes exercised only against fake LDAP/SAMR interfaces."""

from importlib import import_module
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry
from impacket.dcerpc.v5.ndr import NDRULONG

from nxc.playbooks.results import ResultStatus


def entry(dn):
    result = SearchResultEntry()
    result["objectName"] = dn
    result["attributes"][0]["type"] = "distinguishedName"
    result["attributes"][0]["vals"][0] = dn
    return result


@pytest.mark.parametrize("remove", [False, True])
@pytest.mark.parametrize("failure", [None, "lookup", "modify"])
def test_ldap_group_change_tracks_acknowledgment(remove, failure):
    code = import_module("nxc.modules.modify-group")
    module = code.NXCModule()
    context = SimpleNamespace(protocol="ldap", log=Mock())
    module.options(context, {"USER": "alice*(test)", "GROUP": "group", "REMOVE": str(remove)})
    conn = SimpleNamespace(host="offline.invalid", search=Mock(side_effect=[[entry("CN=Alice")], [entry("CN=Group")]]), last_search_error="partial search" if failure == "lookup" else None, ldap_connection=Mock())
    conn.ldap_connection.modify.return_value = True
    if failure == "modify":
        conn.ldap_connection.modify.side_effect = RuntimeError("modify denied")
    result = module.on_login(context, conn)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert result.data.completed is (failure is None)
    assert conn.search.call_args_list[0].kwargs["searchFilter"] == r"(sAMAccountName=alice\2a\28test\29)"
    if failure == "lookup":
        conn.ldap_connection.modify.assert_not_called()
    else:
        conn.ldap_connection.modify.assert_called_once_with("CN=Group", {"member": [(code.MODIFY_DELETE if remove else code.MODIFY_ADD, ["CN=Alice"])]})


def test_samr_cleanup_failure_retains_completed_change(monkeypatch):
    code = import_module("nxc.modules.modify-group")
    rpc = Mock()
    rpc.disconnect.side_effect = RuntimeError("disconnect failed")
    monkeypatch.setattr(code, "NXCRPCConnection", Mock(return_value=Mock(connect=Mock(return_value=rpc))))
    for name, value in [("hSamrConnect", {"ServerHandle": "server"}), ("hSamrLookupDomainInSamServer", {"DomainId": "sid"}), ("hSamrOpenDomain", {"DomainHandle": "domain"}), ("hSamrOpenGroup", {"GroupHandle": "group"})]:
        monkeypatch.setattr(code.samr, name, Mock(return_value=value))
    user_rid, group_rid = NDRULONG(), NDRULONG()
    user_rid["Data"], group_rid["Data"] = 1001, 512
    monkeypatch.setattr(code.samr, "hSamrLookupNamesInDomain", Mock(side_effect=[{"RelativeIds": {"Element": [user_rid]}}, {"RelativeIds": {"Element": [group_rid]}}]))
    add, close = Mock(), Mock()
    monkeypatch.setattr(code.samr, "hSamrAddMemberToGroup", add)
    monkeypatch.setattr(code.samr, "hSamrCloseHandle", close)
    module = code.NXCModule()
    context = SimpleNamespace(protocol="smb", log=Mock())
    module.options(context, {"USER": "alice", "GROUP": "group"})
    result = module.on_login(context, SimpleNamespace(host="offline.invalid", domain="EXAMPLE"))
    assert result.status is ResultStatus.FAILED
    assert result.data.completed
    assert result.data.user_rid == 1001
    assert result.data.group_rid == 512
    assert [call.args[1] for call in close.call_args_list] == ["group", "domain", "server"]
    add.assert_called_once_with(rpc, "group", 1001, 0x7)
