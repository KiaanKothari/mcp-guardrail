"""The core stdio gateway.

An MCP client (Claude Desktop, Claude Code, etc.) normally launches an
MCP server as a subprocess and talks to it directly over stdin/stdout
using newline-delimited JSON-RPC 2.0 messages. This proxy sits in
between: instead of pointing the client at the real server command, you
point it at ``mcp-guardrail run -- <real command>``. Guardrail spawns
the real server itself, and every message that flows client -> server
passes through here first.

The only messages we act on are ``tools/call`` requests -- everything
else (initialize, list_tools, notifications, and all server -> client
traffic) is passed through untouched. When a ``tools/call`` is denied by
policy, we never forward it to the real server at all; instead we write
a JSON-RPC error response directly back to the client, so from the
client's point of view it looks exactly like the server itself refused
the call.

This targets the standard newline-delimited JSON-RPC stdio transport.
Servers that use a different framing (e.g. Content-Length-prefixed,
LSP-style) would need a small adjustment to the read loop.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import IO, Optional

from .audit import AuditLog
from .policy import Policy

TOOLS_CALL_METHOD = "tools/call"


def _extract_tool_name(params: dict) -> Optional[str]:
    if not isinstance(params, dict):
        return None
    # Most MCP servers use "name"; keep this permissive since the spec
    # has shifted before and forks vary.
    return params.get("name") or params.get("tool") or params.get("tool_name")


def _extract_arg_keys(params: dict) -> list:
    if not isinstance(params, dict):
        return []
    args = params.get("arguments")
    if isinstance(args, dict):
        return sorted(args.keys())
    return []


def make_denial_response(request_id, tool_name: str, reason: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32001,
            "message": f"blocked by mcp-guardrail policy: tool '{tool_name}' is not allowed",
            "data": {"tool": tool_name, "reason": reason},
        },
    }


class GuardrailProxy:
    def __init__(
        self,
        command: list,
        policy: Policy,
        audit_log: AuditLog,
        verbose: bool = False,
        client_in: IO = None,
        client_out: IO = None,
    ):
        self.command = command
        self.policy = policy
        self.audit_log = audit_log
        self.verbose = verbose
        # Defaults let production code use real stdio while tests inject
        # in-memory streams.
        self.client_in = client_in if client_in is not None else sys.stdin
        self.client_out = client_out if client_out is not None else sys.stdout
        self.process = None

    def _log_stderr(self, msg: str):
        if self.verbose:
            print(f"[mcp-guardrail] {msg}", file=sys.stderr, flush=True)

    def run(self) -> int:
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit, so the wrapped server's own logs still show up
            text=True,
            bufsize=1,
        )
        self._log_stderr(f"spawned wrapped server: {' '.join(self.command)}")

        server_to_client = threading.Thread(
            target=self._pump_server_to_client, daemon=True
        )
        server_to_client.start()

        try:
            self._pump_client_to_server()
        finally:
            if self.process.stdin:
                try:
                    self.process.stdin.close()
                except Exception:
                    pass
            self.process.wait()
            server_to_client.join(timeout=2)

        return self.process.returncode or 0

    def _pump_client_to_server(self):
        """Read JSON-RPC lines from the client (our stdin) and either
        forward them to the wrapped server or block them per policy."""
        for line in self.client_in:
            line = line.rstrip("\n")
            if not line.strip():
                continue

            forwarded_line, denial = self._handle_client_line(line)

            if denial is not None:
                self._write_client(json.dumps(denial))
                continue

            if self.process.stdin:
                self.process.stdin.write(forwarded_line + "\n")
                self.process.stdin.flush()

    def _handle_client_line(self, line: str):
        """Returns (line_to_forward, denial_response_or_None)."""
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            # Not JSON at all -- pass it through rather than dropping it;
            # guardrail only judges well-formed JSON-RPC tool calls.
            return line, None

        method = message.get("method")
        if method != TOOLS_CALL_METHOD:
            return line, None

        params = message.get("params") or {}
        tool_name = _extract_tool_name(params) or "<unknown>"
        arg_keys = _extract_arg_keys(params)
        request_id = message.get("id")

        decision = self.policy.decide(tool_name)
        self.audit_log.record(
            tool=tool_name,
            action=decision.action,
            reason=decision.reason,
            request_id=request_id,
            arg_keys=arg_keys,
        )
        self._log_stderr(f"{decision.action.upper():5s} {tool_name} ({decision.reason})")

        if decision.allowed:
            return line, None

        return line, make_denial_response(request_id, tool_name, decision.reason)

    def _pump_server_to_client(self):
        """Pass the wrapped server's stdout straight back to the client."""
        if not self.process.stdout:
            return
        for line in self.process.stdout:
            self._write_client(line.rstrip("\n"))

    def _write_client(self, line: str):
        self.client_out.write(line + "\n")
        self.client_out.flush()
