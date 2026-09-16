#!/usr/bin/env python3
"""Generate an offline HTML report for a completed scanner run."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from html_report import generate_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path, help="scanner output/runs/<run-id> directory")
    parser.add_argument("--output", type=Path, help="output HTML path (default: <run>/report.html)")
    args = parser.parse_args()
    try:
        output = generate_report(args.run_directory, args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({"report_output": str(output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
