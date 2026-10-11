"""Command-line interface for assessing captured Trivy reports."""

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from iac_security_gate.configuration import load_exceptions, load_policy
from iac_security_gate.exporting import write_new_report
from iac_security_gate.reporting import build_assessment
from iac_security_gate.scan_context import load_scan_report


def _iso_date(value: str) -> date:
    try:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() != value:
            raise ValueError
        return parsed
    except ValueError:
        raise argparse.ArgumentTypeError("Expected YYYY-MM-DD") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate Terraform Trivy reports with an explicit policy."
    )
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--exceptions", type=Path, required=True)
    parser.add_argument(
        "--allow-root-change",
        action="store_true",
        help="Explicitly accept different scan roots; warnings remain.",
    )
    parser.add_argument(
        "--evaluation-date",
        type=_iso_date,
        help="Replay at YYYY-MM-DD; defaults to the current UTC date.",
    )
    parser.add_argument("--output", type=Path, help="Create a new JSON report.")
    args = parser.parse_args(argv)

    evaluation_date = args.evaluation_date or datetime.now(timezone.utc).date()

    try:
        report = build_assessment(
            load_scan_report(args.baseline),
            load_scan_report(args.current),
            policy=load_policy(args.policy),
            exceptions=load_exceptions(args.exceptions),
            evaluation_date=evaluation_date,
            allow_root_change=args.allow_root_change,
        )
    except (OSError, ValueError):
        print(
            "Analysis failed: invalid, unreadable or incompatible inputs.",
            file=sys.stderr,
        )
        return 2

    report["configuration"]["evaluation_date_source"] = (
        "explicit_replay" if args.evaluation_date else "utc_clock"
    )
    content = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"

    try:
        if args.output is None:
            sys.stdout.write(content)
        else:
            write_new_report(args.output, content)
            print("Report saved.", file=sys.stderr)
    except OSError:
        print("Report output failed; no successful gate result.", file=sys.stderr)
        return 2
    return 0 if report["gate"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
