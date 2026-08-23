import textwrap

import pytest

from mcp_guardrail.policy import Policy, PolicyError


def write_policy(tmp_path, content):
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(content))
    return p


def test_default_deny_with_no_rules(tmp_path):
    path = write_policy(tmp_path, """
        default: deny
        rules: []
    """)
    policy = Policy.load(path)
    decision = policy.decide("anything.at_all")
    assert decision.action == "deny"
    assert not decision.allowed


def test_exact_rule_match_allows(tmp_path):
    path = write_policy(tmp_path, """
        default: deny
        rules:
          - tool: "github.create_issue"
            action: allow
    """)
    policy = Policy.load(path)
    assert policy.decide("github.create_issue").allowed
    assert not policy.decide("github.delete_repo").allowed


def test_glob_pattern_matches(tmp_path):
    path = write_policy(tmp_path, """
        default: deny
        rules:
          - tool: "database.read_*"
            action: allow
    """)
    policy = Policy.load(path)
    assert policy.decide("database.read_users").allowed
    assert policy.decide("database.read_orders").allowed
    assert not policy.decide("database.write_users").allowed


def test_first_matching_rule_wins(tmp_path):
    # A specific deny listed before a broad allow should still win,
    # since rules are evaluated top to bottom.
    path = write_policy(tmp_path, """
        default: deny
        rules:
          - tool: "github.delete_*"
            action: deny
            note: "never auto-delete"
          - tool: "github.*"
            action: allow
    """)
    policy = Policy.load(path)
    decision = policy.decide("github.delete_repo")
    assert not decision.allowed
    assert decision.reason == "never auto-delete"
    assert policy.decide("github.create_issue").allowed


def test_default_allow_still_lets_explicit_deny_win(tmp_path):
    path = write_policy(tmp_path, """
        default: allow
        rules:
          - tool: "shell.exec"
            action: deny
    """)
    policy = Policy.load(path)
    assert not policy.decide("shell.exec").allowed
    assert policy.decide("anything.else").allowed


def test_invalid_default_action_raises(tmp_path):
    path = write_policy(tmp_path, """
        default: maybe
        rules: []
    """)
    with pytest.raises(PolicyError):
        Policy.load(path)


def test_missing_policy_file_raises(tmp_path):
    with pytest.raises(PolicyError):
        Policy.load(tmp_path / "does_not_exist.yaml")


def test_rule_missing_action_raises(tmp_path):
    path = write_policy(tmp_path, """
        default: deny
        rules:
          - tool: "github.create_issue"
    """)
    with pytest.raises(PolicyError):
        Policy.load(path)
