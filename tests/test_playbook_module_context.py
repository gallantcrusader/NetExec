"""Module hooks reuse the current host context and credential references."""

from argparse import Namespace
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nxc.connection import connection
from nxc.playbooks.results import ActionResult, CredentialRef, ResultStatus
from nxc.playbooks.runner import ConnectionData, HostContext, ProtocolSession
import nxc.playbooks.runner as runner


@dataclass
class ModuleData:
    checked: bool


def test_module_hook_receives_existing_host_and_credential_reference():
    host = HostContext("offline.invalid", [])
    credential = CredentialRef("smb", 7)
    source = SimpleNamespace(host=host, result=ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False, credential=credential)))
    fake = SimpleNamespace(logger=Mock(), playbook_mode=True, playbook_session=source, args=Namespace(protocol="smb"), host=host.target, action_results=[])
    existing_ldap = object()
    host.connect = Mock(return_value=existing_ldap)

    def hook(context, conn):
        assert context.session is source
        assert context.playbook is host
        assert context.credential is credential
        assert context.playbook.ldap(credential=context.credential) is existing_ldap
        return ActionResult("smb", "custom", host.target, ResultStatus.SUCCESS, ModuleData(True))

    module = SimpleNamespace(name="custom", result_type=ModuleData, on_login=hook)
    assert connection.run_module_hook(fake, module, "on_login", SimpleNamespace(), Mock())
    host.connect.assert_called_once_with("ldap", credential=credential)
    assert fake.action_results[0].data.checked


@pytest.mark.parametrize("failure", [False, True])
def test_module_dispatch_restores_prior_session_context(monkeypatch, failure):
    host = HostContext("offline.invalid", [])
    previous = object()
    fake = SimpleNamespace(host=host.target, action_results=[], playbook_session=previous)
    args = Namespace(module=[], module_options=[])
    connected = ActionResult("smb", "connect", host.target, ResultStatus.SUCCESS, ConnectionData(True, True, False))
    session = ProtocolSession(host, "smb", fake, args, None, None, connected)

    def call_modules():
        assert fake.playbook_session is session
        if failure:
            raise RuntimeError("module failed")
        fake.action_results.append(ActionResult("smb", "spider_plus", host.target, ResultStatus.SUCCESS, ModuleData(True)))

    fake.call_modules = call_modules
    monkeypatch.setattr(runner, "ModuleLoader", Mock(return_value=Mock(init_module=Mock(return_value=object()))))
    result = session.module("spider_plus", stop_on_error=False)
    assert result.status is (ResultStatus.FAILED if failure else ResultStatus.SUCCESS)
    assert fake.playbook_session is previous
    assert args.module == []
