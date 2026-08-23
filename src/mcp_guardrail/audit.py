"""Append-only audit logging for guardrail decisions.

Every tool call the proxy sees gets written as one JSON object per line
(JSONL) so it's trivial to tail, grep, or ship to another system later.
"""

from __future__ import annotations

import json
import threading
import time
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

DEFAULT_LOG_PATH = Path.home() / ".mcp-guardrail" / "audit.jsonl"


@dataclass
class AuditEntry:
    timestamp: float
    tool: str
    action: str
    reason: str
    request_id: Optional[str] = None
    arg_keys: Optional[list] = None


class AuditLog:
    """Thread-safe JSONL writer. The proxy has a reader thread and a
    writer thread touching this concurrently, so every write is guarded
    by a lock.
    """

    def __init__(self, path: Path = DEFAULT_LOG_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(
        self,
        tool: str,
        action: str,
        reason: str,
        request_id: Optional[str] = None,
        arg_keys: Optional[list] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            timestamp=time.time(),
            tool=tool,
            action=action,
            reason=reason,
            request_id=str(request_id) if request_id is not None else None,
            arg_keys=arg_keys,
        )
        line = json.dumps(asdict(entry), sort_keys=True)
        with self._lock:
            with self.path.open("a") as f:
                f.write(line + "\n")
        return entry

    def read_all(self) -> list:
        if not self.path.exists():
            return []
        entries = []
        with self.path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries


def summarize(entries: list, limit: int = 10) -> str:
    """Render a human-readable summary of audit entries for the CLI report."""
    if not entries:
        return "No audit log entries yet. Run some traffic through `mcp-guardrail run` first."

    total = len(entries)
    blocked = [e for e in entries if e.get("action") == "deny"]
    allowed = [e for e in entries if e.get("action") == "allow"]
    tool_counts = Counter(e.get("tool", "?") for e in entries)

    lines = []
    lines.append(f"Total calls seen:   {total}")
    lines.append(f"Allowed:            {len(allowed)}")
    lines.append(f"Blocked:            {len(blocked)}")
    lines.append("")
    lines.append("Most-called tools:")
    for tool, count in tool_counts.most_common(5):
        lines.append(f"  {count:>4}  {tool}")

    if blocked:
        lines.append("")
        lines.append(f"Most recent blocked calls (up to {limit}):")
        for e in blocked[-limit:][::-1]:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("timestamp", 0)))
            lines.append(f"  [{ts}] {e.get('tool')} -- {e.get('reason')}")

    return "\n".join(lines)
