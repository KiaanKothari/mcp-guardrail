# 🛡️ MCP Guardrail

### Security for AI Agent Tool Calls

**MCP Guardrail** is a lightweight security gateway for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. It sits between an AI agent and an MCP server to enforce tool-access policies, record agent activity, and detect exposed secrets.

> **Control what your AI agents can do — before the tool call reaches your MCP server.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple)](https://modelcontextprotocol.io/)
[![Security](https://img.shields.io/badge/Security-Guardrail-red)](#security-model)

---

## 🚨 Why MCP Guardrail?

AI agents are increasingly being connected to tools that can:

* Read files
* Access databases
* Modify repositories
* Send messages
* Execute actions
* Access external services

MCP makes connecting AI models to these tools easier.

But greater tool access also creates a security problem:

**What happens when an AI agent calls a tool it should not be allowed to use?**

MCP Guardrail provides a lightweight policy layer between the agent and the MCP server.

```text
┌──────────────┐
│   AI Agent   │
└──────┬───────┘
       │
       │ Tool Call
       ▼
┌──────────────────────────────┐
│       MCP GUARDRAIL          │
│                              │
│  🔒 Policy Enforcement       │
│  📋 Audit Logging            │
│  🔐 Secret Detection         │
└──────────────┬───────────────┘
               │
        Allowed Calls
               │
               ▼
        ┌─────────────┐
        │ MCP Server  │
        └─────────────┘
```

---

# ✨ Features

### 🔒 Policy Enforcement

Control which MCP tools an AI agent is allowed to call.

Example:

```text
github.list_repositories     → ALLOWED
github.create_issue          → ALLOWED
github.delete_repository     → BLOCKED
shell.execute                → BLOCKED
```

This enables a **least-privilege** approach to AI agent tool access.

---

### 📋 Audit Logging

Record tool activity so you can understand what an AI agent attempted to do.

Example:

```text
[2026-08-24 14:32:11] github.list_repositories   ALLOWED
[2026-08-24 14:32:13] github.create_issue        ALLOWED
[2026-08-24 14:32:17] github.delete_repository   BLOCKED
```

Audit logs can help with:

* Debugging
* Security investigations
* Monitoring
* Compliance
* Understanding agent behavior

---

### 🔐 Secret Scanning

Detect potentially sensitive information before it is passed through the tool layer.

Examples of information that may require protection include:

```text
API keys
Access tokens
Private credentials
Environment secrets
Authentication material
```

If a potential secret is detected, the request can be blocked instead of being passed downstream.

---

# ⚡ Quick Start

## 1. Clone the repository

```bash
git clone https://github.com/KiaanKothari/mcp-guardrail.git
cd mcp-guardrail
```

## 2. Create a virtual environment

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

## 3. Install

```bash
pip install -e .
```

---

# 🧪 Example

A simplified policy might look like:

```yaml
allowed_tools:
  - github.list_repositories
  - github.create_issue

denied_tools:
  - github.delete_repository
  - shell.execute
```

An incoming request is evaluated before it reaches the MCP server:

```text
AI Agent
   │
   │ github.create_issue
   ▼
MCP Guardrail
   │
   ├── Policy Check
   │       └── ALLOWED ✓
   │
   ├── Secret Scan
   │       └── CLEAN ✓
   │
   └── Audit Log
           │
           ▼
      MCP Server
```

A prohibited request:

```text
AI Agent
   │
   │ github.delete_repository
   ▼
MCP Guardrail
   │
   └── Policy Check
           │
           └── BLOCKED ✗
```

The MCP server never receives the blocked request.

---

# 🏗️ Architecture

```text
                   ┌──────────────────┐
                   │    AI Agent      │
                   └────────┬─────────┘
                            │
                            ▼
                  ┌─────────────────────┐
                  │    MCP Guardrail    │
                  │                     │
                  │ ┌─────────────────┐ │
                  │ │ Policy Engine   │ │
                  │ └─────────────────┘ │
                  │          ↓          │
                  │ ┌─────────────────┐ │
                  │ │ Secret Scanner  │ │
                  │ └─────────────────┘ │
                  │          ↓          │
                  │ ┌─────────────────┐ │
                  │ │  Audit Logger   │ │
                  │ └─────────────────┘ │
                  └──────────┬──────────┘
                             │
                    Allowed Requests
                             │
                             ▼
                    ┌────────────────┐
                    │   MCP Server   │
                    └────────────────┘
```

---

# 🎯 Design Philosophy

MCP Guardrail is intentionally designed to be **small and focused**.

Rather than trying to become a complete AI security platform, the project focuses on three core responsibilities:

```text
1. Control tool access
2. Detect potentially dangerous information
3. Record what happened
```

The goal is to provide a security layer that can be placed around an MCP deployment without requiring the underlying MCP server to be completely redesigned.

---

# 🔒 Security Model

MCP Guardrail follows a **least-privilege** approach.

AI agents should receive only the tool permissions required to complete their task.

For example:

```text
Agent
  │
  ├── read_database       ✓
  ├── search_documents    ✓
  ├── create_ticket       ✓
  │
  ├── delete_database     ✗
  └── execute_shell       ✗
```

This reduces the potential impact of unintended or malicious tool calls.

### Important

MCP Guardrail is an additional security layer.

It should not replace:

* Authentication
* Authorization
* Network security
* Sandboxing
* Secure credential management
* Infrastructure security
* MCP server security practices

---

# 🧪 Testing

Run the test suite with:

```bash
pytest -q
```

For development:

```bash
pip install -e .
pip install pytest
pytest
```

---

# 🗺️ Roadmap

### v0.1

* [x] Tool policy enforcement
* [x] Audit logging
* [x] Secret scanning
* [ ] Expand automated test coverage
* [ ] Publish package to PyPI
* [ ] Add integration examples

### Future

* [ ] More granular policy rules
* [ ] Configuration-file support
* [ ] Additional MCP integrations
* [ ] Security-focused documentation
* [ ] Performance benchmarking
* [ ] Policy templates for common MCP servers

---

# 🤝 Contributing

MCP Guardrail is currently maintained as a **solo project by Kiaan Kothari**.

If you discover a bug or have an idea for improving the project, feel free to open an issue for discussion.

---

# ⚠️ Disclaimer

MCP Guardrail is an experimental open-source security project.

It is intended for research, development, testing, and educational purposes.

Do not rely on the project as the sole security mechanism for production systems without independently evaluating and testing its security properties.

---

# 📄 License

MCP Guardrail is released under the **MIT License**.

See [LICENSE](LICENSE) for details.

---

# 👨‍💻 Author

**Kiaan Kothari**

Student researcher and developer interested in:

* Artificial Intelligence
* AI Agents
* Cybersecurity
* Machine Learning
* Software Engineering
* Open Source

GitHub: [@KiaanKothari](https://github.com/KiaanKothari)

---

## ⭐ Support the Project

If MCP Guardrail is useful to you:

**⭐ Star the repository**

A star helps other developers discover the project and supports continued development.

[![Star on GitHub](https://img.shields.io/github/stars/KiaanKothari/mcp-guardrail?style=social)](https://github.com/KiaanKothari/mcp-guardrail)

---

### MCP Guardrail

**Give AI agents access to tools — without giving them unlimited power.**
