"""Turn asynchronous screenshot capture into a saved-file result."""

import asyncio
from dataclasses import dataclass
from pathlib import Path

from nxc.playbooks.results import ActionResult, Artifact, ResultStatus


@dataclass
class ScreenshotData:
    path: Path | None
    captured: bool


def capture_screenshot(protocol, action, target, capture):
    try:
        filename = asyncio.run(capture())
        path = Path(str(filename)) if filename is not None else None
        if path is not None and not path.is_file():
            raise OSError(f"Screenshot capture did not create {path}")
        return ActionResult(protocol, action, target, ResultStatus.SUCCESS if path else ResultStatus.NEGATIVE, ScreenshotData(path, path is not None), artifacts=[Artifact(path, "screenshot")] if path else [])
    except Exception as e:
        return ActionResult(protocol, action, target, ResultStatus.FAILED, ScreenshotData(None, False), error=str(e) or type(e).__name__)
