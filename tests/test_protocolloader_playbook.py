"""Check dynamic protocol loading supports dataclass result types."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from nxc.loaders.protocolloader import ProtocolLoader


class TestProtocolLoaderPlaybook(TestCase):
    def test_dataclass_protocol_module_is_registered_and_cached(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "protocol.py"
            path.write_text("from dataclasses import dataclass\n@dataclass\nclass Result:\n    value: int\n", encoding="utf-8")
            loader = ProtocolLoader()
            module = loader.load_protocol(str(path))

            assert module.Result(7).value == 7
            assert loader.load_protocol(str(path)) is module
