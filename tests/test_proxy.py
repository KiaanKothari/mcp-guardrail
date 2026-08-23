import json

from mcp_guardrail.audit import AuditLog
from mcp_guardrail.policy import Policy
from mcp_guardrail.proxy import GuardrailProxy


def make_proxy(tmp_path, policy_yaml):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_yaml)
    policy = Policy.load(policy_path)
    audit_log = AuditLog(tmp_path / "audit.jsonl")
    # command is never actually spawned by these unit tests, since we
    # call _handle_client_line directly.
    return GuardrailProxy(command=["true"], policy=policy, audit_log=audit_log)


def test_non_tool_call_message_passes_through_untouched(tmp_path):
    proxy = make_proxy(tmp_path, "default: deny\nrules: []\n")
    line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    forwarded, denial = proxy._handle_client_line(line)
    assert forwarded == line
    assert denial is None


def test_allowed_tool_call_is_forwarded(tmp_path):
    proxy = make_proxy(
        tmp_path,
        'default: deny\nrules:\n  - tool: "github.create_issue"\n    action: allow\n',
    )
    line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "github.create_issue", "arguments": {"title": "hi"}},
        }
    )
    forwarded, denial = proxy._handle_client_line(line)
    assert forwarded == line
    assert denial is None


def test_denied_tool_call_produces_error_response_not_forwarded(tmp_path):
    proxy = make_proxy(tmp_path, "default: deny\nrules: []\n")
    line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "shell.exec", "arguments": {"cmd": "rm -rf /"}},
        }
    )
    forwarded, denial = proxy._handle_client_line(line)
    assert denial is not None
    assert denial["id"] == 7
    assert denial["error"]["data"]["tool"] == "shell.exec"


def test_denied_call_is_recorded_in_audit_log(tmp_path):
    proxy = make_proxy(tmp_path, "default: deny\nrules: []\n")
    line = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "shell.exec"}}
    )
    proxy._handle_client_line(line)
    entries = proxy.audit_log.read_all()
    assert len(entries) == 1
    assert entries[0]["action"] == "deny"
    assert entries[0]["tool"] == "shell.exec"


def test_malformed_json_passes_through_without_crashing(tmp_path):
    proxy = make_proxy(tmp_path, "default: deny\nrules: []\n")
    forwarded, denial = proxy._handle_client_line("not json at all")
    assert forwarded == "not json at all"
    assert denial is None
