"""Exercise common serialization using directory data and custom module hooks."""

import json
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest
from impacket.ldap.ldapasn1 import SearchResultEntry

from nxc.connection import connection
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.playbooks.results import ActionResult, ResultStatus, json_value


@dataclass
class Payload:
    value: object


def test_ldap_guid_query_serializes_without_losing_typed_data():
    guid = UUID("12345678-1234-5678-1234-567812345678")
    entry = SearchResultEntry()
    entry["objectName"] = "CN=User,DC=example,DC=test"
    entry["attributes"][0]["type"] = "objectGUID"
    entry["attributes"][0]["vals"][0] = guid.bytes
    protocol = ProtocolLoader().load_protocol("nxc/protocols/ldap.py")
    fake = SimpleNamespace(args=SimpleNamespace(query=["(objectClass=user)", "objectGUID"]), logger=Mock(), search=Mock(return_value=[entry]), host="dc.example.test", playbook_mode=True, last_search_error=None)
    result = protocol.ldap.query(fake)
    assert result.data.entries[0]["objectGUID"] == guid
    saved = json.loads(json.dumps(result.to_dict()))
    assert saved["data"]["entries"][0]["objectGUID"] == str(guid)
    assert result.status is ResultStatus.SUCCESS


def test_serialization_does_not_deepcopy_custom_values():
    class Unsupported:
        def __deepcopy__(self, memo):
            raise AssertionError("Result validation must not invoke deepcopy")

    with pytest.raises(TypeError, match="Unsupported playbook result value: Unsupported"):
        json_value(Payload(Unsupported()))


@pytest.mark.parametrize("mode", ["captured", "exception", "invalid_contract"])
def test_hook_origin_survives_capture_and_failure(mode):
    def on_admin_login(context, conn):
        if mode == "exception":
            raise RuntimeError("hook failed")
        return {"value": 2}

    module = SimpleNamespace(name="custom", on_admin_login=on_admin_login)
    if mode == "invalid_contract":
        module.result_type = Payload
    fake = SimpleNamespace(logger=Mock(), playbook_mode=True, action_results=[], args=SimpleNamespace(protocol="smb"), host="offline.invalid")
    connection.run_module_hook(fake, module, "on_admin_login", SimpleNamespace(), Mock())
    result = fake.action_results[0]
    assert result.hook == "on_admin_login"
    assert result.to_dict()["hook"] == "on_admin_login"
    assert result.status is (ResultStatus.SUCCESS if mode == "captured" else ResultStatus.FAILED)


def test_non_module_result_has_no_hook():
    result = ActionResult("smb", "shares", "offline.invalid", ResultStatus.SUCCESS, Payload([]))
    assert result.to_dict()["hook"] is None
