"""Common, serializable result types for protocol actions and modules."""

import base64
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date, datetime
from enum import Enum
from decimal import Decimal
from pathlib import Path
from typing import Any, Generic, TypeVar
from uuid import UUID


class ResultStatus(str, Enum):
    SUCCESS = "success"
    NEGATIVE = "negative"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class CredentialRef:
    """Identify a stored credential in a protocol's workspace database."""

    protocol: str
    id: int


@dataclass(frozen=True)
class Artifact:
    """Identify a file written by an action or module."""

    path: Path
    kind: str


@dataclass(frozen=True)
class OutputEvent:
    """One message emitted while an action or module runs."""

    level: str
    message: str


@dataclass(frozen=True)
class OpaqueValue:
    """A return value that cannot be represented directly in JSON."""

    type_name: str
    representation: str


@dataclass(frozen=True)
class ParsedRecord:
    """One legacy output message parsed into a predictable shape."""

    level: str
    kind: str
    value: Any
    key: str | None = None


@dataclass(frozen=True)
class RetiredModuleData:
    """A retired entry point and the supported replacement to choose explicitly."""

    replacement: str


@dataclass
class CapturedData:
    """Baseline structured data for legacy actions and modules."""

    events: list[OutputEvent]
    return_value: Any = None
    records: list[ParsedRecord] = field(default_factory=list)
    fields: dict[str, list[Any]] = field(default_factory=dict)

    def values(self, key: str) -> list[Any]:
        """Return values parsed from legacy ``name: value`` output."""
        return self.fields.get(normalize_output_key(key), [])

    def contains(self, phrase: str, *, level: str | None = None) -> bool:
        """Check raw messages when a module has no semantic result contract."""
        return any(phrase.casefold() in event.message.casefold() for event in self.events if level is None or event.level == level)


def normalize_output_key(key: str) -> str:
    """Normalize labels consistently for field storage and lookup."""
    return "_".join(key.casefold().split())


Data = TypeVar("Data")


@dataclass
class ActionResult(Generic[Data]):
    """One action's outcome and action-specific typed data."""

    protocol: str
    action: str
    target: str
    status: ResultStatus
    data: Data
    artifacts: list[Artifact] = field(default_factory=list)
    error: str | None = None
    schema_version: int = 1
    inputs: dict[str, Any] = field(default_factory=dict)
    kind: str = "typed"
    events: list[OutputEvent] = field(default_factory=list)
    hook: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is ResultStatus.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        """Convert a result to JSON-compatible values without losing binary data."""
        return json_value(self)


def json_value(value: Any) -> Any:
    """Convert supported typed result values to JSON-compatible objects."""
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: json_value(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (Path, UUID, Decimal)):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Unsupported playbook result value: {type(value).__name__}")
