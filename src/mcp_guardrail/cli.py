"""Command-line entry point.

Subcommands:
  mcp-guardrail init                     write a starter policy.yaml
  mcp-guardrail run --policy P -- CMD...  wrap a real MCP server command
  mcp-guardrail scan PATH                scan config file(s) for hardcoded secrets
  mcp-guardrail report                   summarize the audit log
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .audit import AuditLog, DEFAULT_LOG_PATH, summarize
from .policy import DEFAULT_POLICY_TEMPLATE, Policy, PolicyError
from .proxy import GuardrailProxy
from .scan import scan_path


def _cmd_init(args) -> int:
    target = Path(args.output)
    if target.exists() and not args.force:
        print(f"refusing to overwrite existing file: {target} (use --force)", file=sys.stderr)
        return 1
    target.write_text(DEFAULT_POLICY_TEMPLATE)
    print(f"wrote starter policy to {target}")
    return 0


def _cmd_run(args) -> int:
    if not args.command:
        print("error: no server command given. Usage: mcp-guardrail run --policy P -- <command...>", file=sys.stderr)
        return 2

    try:
        policy = Policy.load(Path(args.policy))
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 1

    audit_log = AuditLog(Path(args.log))
    proxy = GuardrailProxy(
        command=list(args.command),
        policy=policy,
        audit_log=audit_log,
        verbose=args.verbose,
    )
    return proxy.run()


def _cmd_scan(args) -> int:
    findings = scan_path(Path(args.path))
    if not findings:
        print(f"no likely secrets found in {args.path}")
        return 0

    print(f"found {len(findings)} possible hardcoded secret(s):\n")
    for f in findings:
        print(f"  {f}")
    print(
        "\nThese are heuristic matches -- verify each one before rotating anything. "
        "Move real credentials into environment variables or your OS keychain instead "
        "of an MCP server config file."
    )
    return 1  # non-zero so this is CI-friendly (fails the check on findings)


def _cmd_report(args) -> int:
    log = AuditLog(Path(args.log))
    entries = log.read_all()
    print(summarize(entries, limit=args.limit))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-guardrail",
        description="An open-source policy gateway, audit log, and secret scanner for MCP servers.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_init = sub.add_parser("init", help="write a starter policy.yaml")
    p_init.add_argument("-o", "--output", default="policy.yaml", help="where to write the policy file")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing file")
    p_init.set_defaults(func=_cmd_init)

    p_run = sub.add_parser(
        "run",
        help="wrap a real MCP server command with the policy gateway",
        description=(
            "Wrap a real MCP server command. Point your MCP client (Claude Desktop, "
            "Claude Code, etc.) at `mcp-guardrail run --policy policy.yaml -- <real command>` "
            "instead of the real command directly."
        ),
    )
    p_run.add_argument("-p", "--policy", default="policy.yaml", help="path to policy.yaml")
    p_run.add_argument("-l", "--log", default=str(DEFAULT_LOG_PATH), help="path to the audit log (JSONL)")
    p_run.add_argument("-v", "--verbose", action="store_true", help="print allow/deny decisions to stderr")
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="the real MCP server command, after --")
    p_run.set_defaults(func=_cmd_run)

    p_scan = sub.add_parser("scan", help="scan a file or directory for hardcoded secrets")
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.set_defaults(func=_cmd_scan)

    p_report = sub.add_parser("report", help="summarize the audit log")
    p_report.add_argument("-l", "--log", default=str(DEFAULT_LOG_PATH), help="path to the audit log (JSONL)")
    p_report.add_argument("-n", "--limit", type=int, default=10, help="how many recent blocked calls to show")
    p_report.set_defaults(func=_cmd_report)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # argparse.REMAINDER keeps a leading "--" if the user typed one;
    # strip it so `run --policy p -- cmd arg1` and `run --policy p cmd arg1`
    # both work.
    if args.subcommand == "run" and args.command and args.command[0] == "--":
        args.command = args.command[1:]

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
