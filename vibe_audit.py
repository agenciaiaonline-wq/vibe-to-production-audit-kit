"""CLI entrypoint for Vibe-to-Production Security Auditor."""

import argparse
import json
from pathlib import Path
import sys

from auditor.scanner import scan_directory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit AI-generated repositories for exposed client secrets, RLS gaps, and unsafe sinks."
    )
    parser.add_argument("target", nargs="?", default=".", help="Directory path to scan (default: current directory)")
    parser.add_argument("--json", action="store_true", help="Output structured JSON report")
    parser.add_argument("--fail-under", type=int, default=80, help="Exit non-zero if audit score falls below threshold")
    args = parser.parse_args(argv)

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: target path does not exist: {target_path}", file=sys.stderr)
        return 2

    report = scan_directory(target_path)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Vibe-to-Production Audit | Score: {report['score']}/100 | Files: {report['scanned_files']}")
        if not report["findings"]:
            print("PASSED: 0 security findings detected.")
        for item in report["findings"]:
            print(f"[{item['severity']}] {item['rule_id']} {item['file']}:{item['line']} - {item['description']}")

    return 0 if report["score"] >= args.fail_under else 1


if __name__ == "__main__":
    raise SystemExit(main())
