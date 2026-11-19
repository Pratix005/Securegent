"""
Human approvals across processes, through a shared folder.

The guard (e.g. inside the MCP proxy) writes a request to  <state>/approvals/pending/<id>.json
and waits. The dashboard lists pending requests and writes the answer to
<state>/approvals/decided/<id>.json. No answer before the timeout means "deny".

Stdlib only, works on Windows/macOS/Linux, and any number of proxies can share one dashboard.
"""

import json
import os
import time
import uuid
from pathlib import Path

DEFAULT_STATE_DIR = Path.home() / ".securegent"


def _dirs(state_dir: str | Path) -> tuple[Path, Path]:
    base = Path(state_dir) / "approvals"
    pending, decided = base / "pending", base / "decided"
    pending.mkdir(parents=True, exist_ok=True)
    decided.mkdir(parents=True, exist_ok=True)
    return pending, decided


def _write_atomic(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, default=str), encoding="utf-8")
    os.replace(tmp, path)


def _valid_id(request_id: str) -> bool:
    return len(request_id) == 32 and all(c in "0123456789abcdef" for c in request_id)


class FileApprover:
    """An approver for Guard(..., approver=FileApprover()) that waits for the dashboard."""

    def __init__(self, state_dir: str | Path = DEFAULT_STATE_DIR, timeout: float = 120, poll: float = 0.5):
        self.state_dir = Path(state_dir)
        self.timeout = timeout
        self.poll = poll

    def __call__(self, request: dict) -> bool:
        pending, decided = _dirs(self.state_dir)
        request_id = uuid.uuid4().hex
        now = time.time()
        _write_atomic(pending / f"{request_id}.json",
                      {"id": request_id, "created": now, "expires": now + self.timeout, "request": request})
        answer_file = decided / f"{request_id}.json"
        try:
            while time.time() < now + self.timeout:
                if answer_file.exists():
                    try:
                        answer = json.loads(answer_file.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, OSError):
                        time.sleep(self.poll)
                        continue
                    return answer.get("approved") is True
                time.sleep(self.poll)
            return False   # nobody answered in time: deny
        finally:
            (pending / f"{request_id}.json").unlink(missing_ok=True)
            answer_file.unlink(missing_ok=True)


def list_pending(state_dir: str | Path = DEFAULT_STATE_DIR) -> list[dict]:
    pending, _ = _dirs(state_dir)
    items = []
    for f in pending.glob("*.json"):
        try:
            item = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if item.get("expires", 0) < time.time():
            continue
        items.append(item)
    return sorted(items, key=lambda i: i.get("created", 0))


def decide(request_id: str, approved: bool, state_dir: str | Path = DEFAULT_STATE_DIR) -> bool:
    """Answer a pending request. Returns False if it no longer exists."""
    if not _valid_id(request_id):
        return False
    pending, decided = _dirs(state_dir)
    if not (pending / f"{request_id}.json").exists():
        return False
    _write_atomic(decided / f"{request_id}.json", {"approved": bool(approved), "decided": time.time()})
    return True
