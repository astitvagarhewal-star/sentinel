"""Terminal interface. It exposes only passive, scope-gated operations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.orchestrator import audit_target, passive_inventory
from sentinel.persistence import AuditStore
from sentinel.reports import render_json, render_markdown, write_report
from sentinel.scope import ScopeError, load_scope, validate_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="Scope-gated passive web security auditing")
    commands = parser.add_subparsers(dest="command", required=True)
    scope = commands.add_parser("scope", help="validate a scope file")
    scope_subcommands = scope.add_subparsers(dest="scope_command", required=True)
    validate = scope_subcommands.add_parser("validate")
    validate.add_argument("--scope", required=True, type=Path)
    audit = commands.add_parser("audit", help="run a passive audit")
    audit.add_argument("target_url")
    audit.add_argument("--scope", required=True, type=Path)
    audit.add_argument("--output", default=Path("reports"), type=Path)
    audit.add_argument("--database", default=Path("sentinel.db"), type=Path)
    run = commands.add_parser("run", help="inspect a stored audit run")
    run_subcommands = run.add_subparsers(dest="run_command", required=True)
    show = run_subcommands.add_parser("show")
    show.add_argument("run_id")
    show.add_argument("--database", default=Path("sentinel.db"), type=Path)
    report = commands.add_parser("report", help="export a stored audit report")
    report_subcommands = report.add_subparsers(dest="report_command", required=True)
    export = report_subcommands.add_parser("export")
    export.add_argument("run_id")
    export.add_argument("--format", choices=("json", "markdown"), required=True)
    export.add_argument("--output", required=True, type=Path)
    export.add_argument("--database", default=Path("sentinel.db"), type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scope":
        try:
            scope = load_scope(args.scope)
            print(json.dumps(scope.as_dict(), indent=2, default=list))
            return 0
        except (OSError, ScopeError) as exc:
            print(f"scope validation failed: {exc}")
            return 2
    if args.command == "audit":
        try:
            scope = load_scope(args.scope)
            validate_url(args.target_url, scope, resolve_dns=False)
        except (OSError, ScopeError) as exc:
            print(f"audit blocked: {exc}")
            return 2
        result = audit_target(args.target_url, scope)
        store = AuditStore(args.database)
        try:
            store.save(args.target_url, scope, result)
        finally:
            store.close()
        payload = {"run_id": result.run_id, "errors": list(result.errors), "inventory": passive_inventory(result)}
        args.output.mkdir(parents=True, exist_ok=True)
        write_report(args.output / f"{result.run_id}.json", json.dumps(payload, indent=2) + "\n")
        print(json.dumps(payload, indent=2))
        return 0 if not result.errors else 1
    store = AuditStore(args.database)
    try:
        record = store.get_run(args.run_id)
    finally:
        store.close()
    if record is None:
        print("run not found")
        return 2
    if args.command == "run":
        print(render_json(record))
        return 0
    content = render_json(record) if args.format == "json" else render_markdown(record)
    write_report(args.output, content)
    print(f"wrote {args.format} report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
