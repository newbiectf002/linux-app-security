#!/usr/bin/env python3
"""Export normalized findings as DefectDojo Generic Findings Import JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from defectdojo_export import export_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings", type=Path, help="normalized/findings.json to export")
    parser.add_argument("--output", type=Path, help="output JSON path")
    args = parser.parse_args()
    try:
        output = export_file(args.findings, args.output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"defectdojo_output": str(output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
