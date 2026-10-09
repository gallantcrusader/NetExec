"""Common, serializable result types for protocol actions and modules."""

import base64
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date, datetime
from enum import Enum, StrEnum
from decimal import Decimal
from pathlib import Path
from typing import Any, Generic, TypeVar
from uuid import UUID


class ResultStatus(StrEnum):
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
    index: int | None = None

    @property
    def ok(self) -> bool:
        return self.status is ResultStatus.SUCCESS

    @property
    def rows(self) -> list[dict]:
        """Tabular payload as a list of dict rows, one dict per row.

        Works for query-style actions regardless of how the protocol stores the
        payload: ``columns`` + positional ``rows`` (mssql), ``attributes`` +
        ``entries`` (ldap), ``records`` (wmi), or a ``rows`` list that is already
        dict-like. Duplicate column names collapse (last value wins); use
        ``self.data`` directly when positional fidelity matters.
        """
        return tabular_rows(self.data)

    def one(self) -> dict:
        """Return the single tabular row as a dict, or raise if there is not exactly one."""
        rows = self.rows
        if len(rows) != 1:
            raise ValueError(f"{self.protocol}.{self.action} returned {len(rows)} rows; expected exactly one")
        return rows[0]

    def to_dict(self) -> dict[str, Any]:
        """Convert a result to JSON-compatible values without losing binary data."""
        return json_value(self)


def tabular_rows(data: Any) -> list[dict]:
    """Adapt a typed action payload to a uniform list of dict rows.

    Recognizes the tabular shapes NetExec actions use: ``attributes``/``entries``
    (ldap), ``records`` (wmi), and ``columns``/``rows`` (mssql). A bare ``rows``
    list whose elements are already mappings is returned as dicts. Raises
    ``TypeError`` for payloads that are not tabular.
    """
    entries = getattr(data, "entries", None)
    if isinstance(entries, list):
        return [dict(entry) for entry in entries]
    records = getattr(data, "records", None)
    if isinstance(records, list):
        return [dict(record) for record in records]
    rows = getattr(data, "rows", None)
    if isinstance(rows, list):
        columns = getattr(data, "columns", None)
        if columns is not None:
            columns = list(columns)
            return [dict(zip(columns, row, strict=False)) for row in rows]
        return [dict(row) for row in rows]
    raise TypeError(f"{type(data).__name__} has no tabular rows (expected columns/rows, attributes/entries, or records)")


class ModuleResult:
    """Uniform container for the one-or-more results a module run produces.

    A module hook may emit several :class:`ActionResult` objects (one per host
    hook). This container is always what ``session.module(...)`` returns so a
    caller never has to branch on "single vs list". It is iterable and indexable
    over the individual results, and single-result attribute access
    (``status``/``data``/``error``/``rows``/``one()``/``index``/...) transparently
    proxies to the sole result, raising a clear error if there is more than one.
    """

    def __init__(self, results):
        self.results = list(results)

    def __iter__(self):
        return iter(self.results)

    def __len__(self):
        return len(self.results)

    def __getitem__(self, item):
        return self.results[item]

    def __bool__(self):
        return bool(self.results)

    @property
    def first(self) -> "ActionResult | None":
        return self.results[0] if self.results else None

    @property
    def ok(self) -> bool:
        """True when the module produced results and every one succeeded."""
        return bool(self.results) and all(result.ok for result in self.results)

    def _single(self) -> "ActionResult":
        if len(self.results) != 1:
            raise ValueError(f"module produced {len(self.results)} results; iterate the results instead of reading a single value")
        return self.results[0]

    @property
    def error(self) -> str | None:
        """First failure message across the produced results, if any."""
        for result in self.results:
            if result.error:
                return result.error
        return None

    @property
    def events(self) -> list[OutputEvent]:
        collected: list[OutputEvent] = []
        for result in self.results:
            collected.extend(result.events)
        return collected

    @property
    def status(self) -> ResultStatus:
        return self._single().status

    @property
    def data(self) -> Any:
        return self._single().data

    @property
    def inputs(self) -> dict:
        return self._single().inputs

    @property
    def artifacts(self) -> list[Artifact]:
        collected: list[Artifact] = []
        for result in self.results:
            collected.extend(result.artifacts)
        return collected

    @property
    def hook(self) -> str | None:
        return self._single().hook

    @property
    def index(self) -> int | None:
        return self._single().index

    @property
    def rows(self) -> list[dict]:
        return self._single().rows

    def one(self) -> dict:
        return self._single().one()

    def to_dict(self) -> list[dict]:
        return [result.to_dict() for result in self.results]


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
