"""Command-line interface for offline Kubernetes manifest posture analysis."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from basalt_core import ScanContext, Severity, available_formats, get_emitter, load_catalog

from .registry import CHECKS, Check
from .scanner import KubernetesScanner, __version__


def _cmd_scan(args: argparse.Namespace) -> int:
    checks = list(CHECKS)
    if args.rule:
        unknown_rules = sorted(set(args.rule) - {check.rule_id for check in checks})
        if unknown_rules:
            print(f"unknown rule ids: {', '.join(unknown_rules)}", file=sys.stderr)
            return 2
    context = ScanContext(paths=args.paths, rule_filter=args.rule or [])
    result = KubernetesScanner(checks).run(context)
    if args.dedupe:
        result = result.deduplicate()
    emitter = get_emitter(args.format)
    output = emitter.emit_json(result, indent=None if args.compact else 2)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"wrote {args.output} ({emitter.format})", file=sys.stderr)
    else:
        print(output)
    counts = result.severity_counts()
    summary = "  ".join(f"{key}={value}" for key, value in counts.items())
    print(
        f"{len(result.findings)} findings across {len(checks)} checks  [{summary}]  "
        f"max risk {result.max_risk()}",
        file=sys.stderr,
    )
    for error in result.metadata.errors:
        print(f"error: {error}", file=sys.stderr)
    if args.fail_on:
        threshold = Severity.from_any(args.fail_on).rank
        if any(finding.severity.rank >= threshold for finding in result.findings):
            return 1
    return 0


def _cmd_checks(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    by_area: dict[str, list[type[Check]]] = {}
    for cls in CHECKS:
        area = cls.rule_id.split(".", 1)[0]
        by_area.setdefault(area, []).append(cls)
    for area in sorted(by_area):
        print(f"\n{area}")
        for cls in sorted(by_area[area], key=lambda check: check.rule_id):
            unresolved = catalog.unknown(cls.control_ids)
            suffix = "  [unknown controls: " + ", ".join(unresolved) + "]" if unresolved else ""
            kinds = ", ".join(cls.kinds)
            print(f"  {cls.rule_id:<46} {cls.severity.value:<8} {kinds}{suffix}")
            if args.verbose:
                print(f"      controls: {', '.join(cls.control_ids)}")
    print(f"\n{len(CHECKS)} checks across {len(by_area)} posture areas")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="basalt-k8s", description="Offline Kubernetes manifest posture scanner."
    )
    parser.add_argument("--version", action="version", version=f"basalt-k8s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Analyze Kubernetes YAML without cluster access")
    p_scan.add_argument("paths", nargs="*", default=["."], help="YAML file or directory targets")
    p_scan.add_argument("--rule", nargs="+", help="Run only these rule identifiers")
    p_scan.add_argument("--format", default="sarif", choices=available_formats())
    p_scan.add_argument("-o", "--output", help="Write output to a file instead of stdout")
    p_scan.add_argument("--dedupe", action="store_true")
    p_scan.add_argument("--compact", action="store_true")
    p_scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Exit 1 if any finding is at or above this severity",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_checks = sub.add_parser("checks", help="List every registered Kubernetes posture check")
    p_checks.add_argument("-v", "--verbose", action="store_true")
    p_checks.set_defaults(func=_cmd_checks)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface and return its process exit status."""

    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
