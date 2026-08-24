# Security Model

MCP Guardrail is designed to provide a lightweight security layer between AI agents and MCP servers.

## Core protections

- Tool-level allow and deny policies
- Audit logging of tool activity
- Secret detection
- Explicit policy enforcement

## Security philosophy

MCP Guardrail follows a least-privilege approach: AI agents should only be allowed to access the tools and actions they actually need.

## Limitations

MCP Guardrail is an additional security layer and should not be considered a complete security solution. Operators should still use appropriate authentication, authorization, sandboxing, network controls, and secret-management practices.

## Responsible disclosure

If you discover a security vulnerability, please report it privately to the repository owner rather than publicly disclosing the vulnerability before it can be investigated.
