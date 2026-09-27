"""Capture legacy NetExec output as typed playbook events."""

import contextlib
import json
import re

from nxc.playbooks.results import ActionResult, CapturedData, OpaqueValue, OutputEvent, ParsedRecord, ResultStatus, json_value, normalize_output_key


CAPTURED_LEVELS = {"debug", "info", "display", "highlight", "success", "fail", "error", "warning", "warn", "critical", "exception"}
FAILED_LEVELS = {"fail", "error", "critical", "exception"}
KEY_VALUE = re.compile(r"^([A-Za-z][A-Za-z0-9 _./-]{0,63}):\s+(.+)$")


class RecordingLogger:
    """Forward logging unchanged while retaining per-step messages."""

    def __init__(self, logger, events=None):
        self.logger = logger
        self.events = [] if events is None else events

    def __getattr__(self, name):
        attribute = getattr(self.logger, name)
        if name not in CAPTURED_LEVELS or not callable(attribute):
            return attribute

        def record(message, *args, **kwargs):
            formatted = str(message)
            if args:
                with contextlib.suppress(TypeError, ValueError):
                    formatted = formatted % args
            self.events.append(OutputEvent(name, formatted))
            return attribute(message, *args, **kwargs)

        return record


def captured_value(value):
    """Keep JSON values intact and describe unsupported Python objects."""
    try:
        return json_value(value)
    except TypeError:
        return OpaqueValue(type(value).__name__, repr(value))


def parse_scalar(value):
    """Convert unambiguous scalar text while retaining other text verbatim."""
    lowered = value.casefold()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("none", "null"):
        return None
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        with contextlib.suppress(ValueError):
            return int(value)
    return value


def parse_events(events):
    """Index common structured forms while retaining original messages in events."""
    records = []
    fields = {}
    for event in events:
        message = event.message.strip()
        if message.startswith(("{", "[")) and message.endswith(("}", "]")):
            with contextlib.suppress(ValueError, RecursionError):
                value = json.loads(message)
                records.append(ParsedRecord(event.level, "json", value))
                if isinstance(value, dict):
                    for key, item in value.items():
                        fields.setdefault(normalize_output_key(str(key)), []).append(item)
                continue
        match = KEY_VALUE.fullmatch(message)
        if match:
            key = normalize_output_key(match.group(1))
            value = parse_scalar(match.group(2))
            records.append(ParsedRecord(event.level, "key_value", value, key))
            fields.setdefault(key, []).append(value)
        else:
            records.append(ParsedRecord(event.level, "text", event.message))
    return records, fields


def captured_result(protocol, action, target, returned, events):
    """Turn a legacy action or module hook into a serializable result."""
    failures = [event.message for event in events if event.level in FAILED_LEVELS]
    records, fields = parse_events(events)
    return ActionResult(
        protocol=protocol,
        action=action,
        target=target,
        status=ResultStatus.FAILED if failures else ResultStatus.SUCCESS,
        data=CapturedData(events=list(events), return_value=captured_value(returned), records=records, fields=fields),
        error="; ".join(failures) if failures else None,
        kind="captured",
        events=list(events),
    )
