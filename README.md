# mcp-guardrail

An open-source policy gateway, audit log, and secret scanner for [MCP](https://modelcontextprotocol.io) (Model Context Protocol) servers.

## Why this exists

MCP is how agents like Claude reach out into the real world -- databases, GitHub, internal
APIs, the filesystem, anything with an MCP server in front of it. Adoption has moved fast in
2026, but the guardrails around it haven't kept up. Recent industry research on MCP deployments
reports that only a minority of setups implement any access scoping for tool permissions, that a
majority expose credentials as plain hardcoded values in server config files, and that most
organizations grant their AI agents broader access than they'd give a human employee doing the
same job.

`mcp-guardrail` is a small, focused answer to that gap: a proxy that sits between your MCP
client and the real MCP server, so you decide what the agent can actually call, you get a
written record of what it did, and you catch a leaked credential in a config file before it
ships.

It does three things:

1. **Enforces a policy** -- an explicit allow/deny list (with glob patterns) for which tools an
   agent is allowed to call. Denied calls never reach the real server.
2. **Keeps an audit log** -- every tool call, allowed or blocked, is written to a local JSONL
   file you can tail, grep, or summarize.
3. **Scans for hardcoded secrets** -- a narrow, purpose-built scanner for the specific mistake of
   pasting a real API key or token into an MCP server's config.

This is the fully open-source core, and it's meant to stay that way. There's no dashboard, no
account, no server to sign up for -- it's a CLI you run yourself.

## Install

```bash
pip install -e .
```

(Not yet published to PyPI -- clone this repo and install locally for now.)

## Quick start

### 1. Write a policy

```bash
mcp-guardrail init
```

This writes a commented starter `policy.yaml`. See `policy.example.yaml` in this repo for a
fuller example. The shape is:

```yaml
default: deny

rules:
  - tool: "github.create_issue"
    action: allow
  - tool: "github.delete_*"
    action: deny
    note: "destructive GitHub actions are never auto-approved"
```

Rules are checked top to bottom; the first pattern that matches a tool name wins. Anything
matching no rule falls back to `default`. Start from `default: deny` and open up only what the
agent actually needs -- that's the whole point.

### 2. Wrap your real MCP server

Wherever your MCP client config currently launches a server directly, point it at
`mcp-guardrail run` instead. For example, in a Claude Desktop / Claude Code style
`mcpServers` config:

```json
{
  "mcpServers": {
    "github": {
      "command": "mcp-guardrail",
      "args": [
        "run", "--policy", "/path/to/policy.yaml", "--",
        "npx", "-y", "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

Guardrail spawns the real server itself and transparently proxies everything between it and
the client. `tools/call` requests get checked against your policy; a denied call never reaches
the real server -- the client gets an error response back immediately instead, as if the server
itself had refused it.

### 3. Check what happened

```bash
mcp-guardrail report
```

```
Total calls seen:   14
Allowed:            11
Blocked:            3

Most-called tools:
     6  github.list_issues
     4  github.create_issue
     3  shell.exec

Most recent blocked calls (up to 10):
  [2026-08-23 10:04:12] shell.exec -- no rule matched; fell back to default action
```

### 4. Scan for hardcoded secrets

```bash
mcp-guardrail scan ~/.config/claude/
```

Checks `.json`, `.yaml`/`.yml`, `.env`, and `.toml` files under the given path for patterns
that look like real API keys, tokens, or private keys (AWS, GitHub, Slack, OpenAI, Anthropic,
PEM private key blocks, and a generic `key/secret/token/password = "..."` heuristic). It skips
obvious placeholders (`YOUR_API_KEY`, `${ENV_VAR}`, `changeme`, `<...>`, etc.) and masks the
matched value in its output. Exits non-zero when it finds something, so it's usable as a CI
check on a repo of MCP configs.

## How the proxy works

An MCP client normally launches a server as a subprocess and talks to it over stdin/stdout using
newline-delimited JSON-RPC 2.0. `mcp-guardrail run` spawns the *real* server itself and sits in
between: client -> guardrail -> real server, and back. Every `tools/call` message is inspected
and checked against your policy before it's forwarded; everything else (`initialize`, tool
listing, notifications, and all server-to-client traffic) passes straight through untouched.

This targets the standard newline-delimited JSON-RPC stdio transport. A server using different
framing would need a small adjustment to the read loop in `proxy.py`.

## What this is not (yet)

This is the open-source core, deliberately scoped small: a proxy, a policy file, a log, a
scanner. It does not include a hosted dashboard, team accounts, SSO, or long-term audit
retention -- if there's ever a paid layer built on top of this, that's where it would live,
sitting next to the free CLI rather than replacing it.

## Contributing

Issues and PRs welcome. Useful directions if you want to dig in: additional secret patterns,
support for Content-Length-framed transports, per-argument policy rules (not just per-tool-name),
and a `--dry-run` mode that logs what *would* be blocked without actually blocking it yet.

## License

MIT -- see `LICENSE`.
