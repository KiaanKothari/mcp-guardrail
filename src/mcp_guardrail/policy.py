"""Policy loading and evaluation.

A policy is a YAML file describing which MCP tools are allowed to be
called through the guardrail proxy. Rules are evaluated in order and the
first match wins; if nothing matches, the policy's ``default`` action is
used.

Example policy.yaml::

    default: deny
    rules:
      - tool: "github.create_issue"
        action: allow
      - tool: "github.delete_*"
        action: deny
        note: "never let the agent delete things unattended"
      - tool: "database.read_*"
        action: allow
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

VALID_ACTIONS = ("allow", "deny")


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


@dataclass
class Rule:
    tool: str
    action: str
    note: Optional[str] = None

    def matches(self, tool_name: str) -> bool:
        return fnmatch.fnmatchcase(tool_name, self.tool)


@dataclass
class Decision:
    tool: str
    action: str
    matched_rule: Optional[Rule] = None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def reason(self) -> str:
        if self.matched_rule is None:
            return "no rule matched; fell back to default action"
        if self.matched_rule.note:
            return self.matched_rule.note
        return f"matched rule for '{self.matched_rule.tool}'"


@dataclass
class Policy:
    default: str = "deny"
    rules: list = field(default_factory=list)

    def __post_init__(self):
        if self.default not in VALID_ACTIONS:
            raise PolicyError(
                f"policy 'default' must be one of {VALID_ACTIONS}, got {self.default!r}"
            )
        for rule in self.rules:
            if rule.action not in VALID_ACTIONS:
                raise PolicyError(
                    f"rule for tool {rule.tool!r} has invalid action {rule.action!r}; "
                    f"must be one of {VALID_ACTIONS}"
                )

    def decide(self, tool_name: str) -> Decision:
        """Evaluate the policy against a tool name. First matching rule wins."""
        for rule in self.rules:
            if rule.matches(tool_name):
                return Decision(tool=tool_name, action=rule.action, matched_rule=rule)
        return Decision(tool=tool_name, action=self.default, matched_rule=None)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        path = Path(path)
        if not path.exists():
            raise PolicyError(f"policy file not found: {path}")
        try:
            raw = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise PolicyError(f"could not parse policy file {path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise PolicyError(f"policy file {path} must contain a YAML mapping at the top level")

        default = raw.get("default", "deny")
        rules_raw = raw.get("rules", []) or []
        if not isinstance(rules_raw, list):
            raise PolicyError("'rules' must be a list")

        rules = []
        for i, r in enumerate(rules_raw):
            if not isinstance(r, dict) or "tool" not in r or "action" not in r:
                raise PolicyError(
                    f"rule #{i} must be a mapping with at least 'tool' and 'action' keys"
                )
            rules.append(Rule(tool=r["tool"], action=r["action"], note=r.get("note")))

        return cls(default=default, rules=rules)


DEFAULT_POLICY_TEMPLATE = """\
# mcp-guardrail policy file
#
# Rules are checked top to bottom; the first one whose "tool" pattern
# matches (glob-style, e.g. "github.*") wins. Anything that matches no
# rule falls back to `default`.
#
# Start from `default: deny` and explicitly allow only what the agent
# actually needs -- that's the whole point of the gateway.

default: deny

rules:
  # - tool: "github.create_issue"
  #   action: allow
  #
  # - tool: "github.delete_*"
  #   action: deny
  #   note: "destructive GitHub actions are never auto-approved"
  #
  # - tool: "filesystem.read_*"
  #   action: allow
"""
