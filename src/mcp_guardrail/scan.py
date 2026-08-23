"""A small, dependency-free secret scanner aimed specifically at MCP
server config files (claude_desktop_config.json, .mcp.json, and
similar), where hardcoded API keys and tokens are a common and
easy-to-miss mistake.

This is deliberately narrow rather than a general-purpose secret
scanner (tools like gitleaks/truffleHog already do that well) -- the
point is to catch the specific case of "I pasted a real credential into
an MCP server's env/args block."
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SCAN_EXTENSIONS = {".json", ".yaml", ".yml", ".env", ".toml"}

# Each pattern: (label, compiled regex). Kept intentionally conservative
# to favor real hits over noise; still expect some false positives on
# genuinely random-looking non-secret strings, which is why matches are
# reported, not auto-deleted.
_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key (heuristic)", re.compile(
        r"aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?", re.IGNORECASE
    )),
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("Generic private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "Generic hardcoded secret assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*"
            r"[\"']([A-Za-z0-9_\-/+]{16,})[\"']"
        ),
    ),
]

_PLACEHOLDER_HINTS = re.compile(
    r"(?i)your[_-]?(api[_-]?key|token|secret|password)|<[^>]+>|xxx+|\$\{|changeme|example|placeholder"
)


@dataclass
class Finding:
    path: str
    line_number: int
    label: str
    preview: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line_number}  [{self.label}]  {self.preview}"


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def scan_text(text: str, path_label: str) -> list:
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if _PLACEHOLDER_HINTS.search(line):
            continue
        for label, pattern in _PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            secret = match.group(1) if match.groups() else match.group(0)
            findings.append(
                Finding(
                    path=path_label,
                    line_number=line_number,
                    label=label,
                    preview=_mask(secret),
                )
            )
    return findings


def iter_scannable_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in SCAN_EXTENSIONS:
            # Skip common noise directories.
            if any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts):
                continue
            yield path


def scan_path(root: Path) -> list:
    root = Path(root)
    all_findings = []
    for file_path in iter_scannable_files(root):
        try:
            text = file_path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        all_findings.extend(scan_text(text, str(file_path)))
    return all_findings
