"""Offline loader checks for custom-module contracts before any execution."""

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import nxc
from nxc.loaders.moduleloader import ModuleLoader
from nxc.playbooks.contracts import ResultContractError


@dataclass
class Data:
    count: int = 0


@pytest.mark.parametrize("declaration", [None, dict, Data()])
@pytest.mark.parametrize("name", ["custom", "spooler"])
def test_custom_contract_rejected_before_options(tmp_path, declaration, name):
    module = SimpleNamespace(name=name, result_type=declaration, options=Mock())
    loader = ModuleLoader(SimpleNamespace(playbook_mode=True), None, Mock())
    loader.load_module = Mock(return_value=module)
    with pytest.raises(ResultContractError, match="dataclass result_type"):
        loader.init_module(str(tmp_path / f"{name}.py"))
    module.options.assert_not_called()


@pytest.mark.parametrize(("builtin", "playbook", "declaration"), [(False, True, Data), (True, True, None), (False, False, None)])
def test_typed_custom_and_legacy_compatibility(tmp_path, builtin, playbook, declaration):
    module = SimpleNamespace(name="sample", result_type=declaration, supported_protocols=["smb"], options=Mock())
    args = SimpleNamespace(playbook_mode=playbook, protocol="smb", module_options=[])
    loader = ModuleLoader(args, None, Mock())
    loader.load_module = Mock(return_value=module)
    directory = Path(nxc.__file__).resolve().parent / "modules" if builtin else tmp_path
    assert loader.init_module(str(directory / "sample.py")) is module
    module.options.assert_called_once()
