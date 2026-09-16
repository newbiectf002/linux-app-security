#!/usr/bin/env python3
"""Run static ELF/shared-object inventory and finding correlation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from elf_inventory import scan  # noqa: E402
from defectdojo_export import export_file  # noqa: E402
from html_report import generate_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="single file or directory to inspect")
    parser.add_argument(
        "--output-dir", type=Path, default=Path("output"),
        help="output root containing runs/<run-id> (default: output)",
    )
    parser.add_argument(
        "--target-root", type=Path,
        help="explicit extracted/live filesystem root used for safe dependency resolution",
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="do not generate the offline report.html artifact",
    )
    parser.add_argument(
        "--profile", choices=("p0", "p1"), default="p1",
        help="p0 core/cross-check tools or p1 full static profile (default: p1)",
    )
    parser.add_argument(
        "--yara-rules", type=Path,
        help="optional YARA rules file (default: rules/elf-review.yar)",
    )
    parser.add_argument(
        "--no-defectdojo", action="store_true",
        help="do not generate defectdojo-generic-findings.json",
    )
    args = parser.parse_args()
    try:
        run_root, normalized = scan(
            args.target, args.output_dir, target_root=args.target_root,
            profile=args.profile, yara_rules=args.yara_rules,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.target.is_file() and normalized["summary"]["unsupported"] == 1:
        parser.error(
            f"unsupported input (expected an ELF executable or shared object): {args.target}; "
            f"inspection evidence retained at {run_root}"
        )
    report_output = None
    defectdojo_output = None
    if not args.no_defectdojo:
        try:
            defectdojo_output = export_file(run_root / "normalized" / "findings.json")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(
                f"scan completed but DefectDojo export failed: {exc}; "
                f"scan output retained at {run_root}", file=sys.stderr,
            )
            return 1
    if not args.no_report:
        try:
            report_output = generate_report(run_root)
        except (OSError, ValueError) as exc:
            print(
                f"scan completed but HTML report generation failed: {exc}; "
                f"scan output retained at {run_root}",
                file=sys.stderr,
            )
            return 1
    result = {
        "run_id": normalized["run_id"],
        "run_root": str(run_root),
        "run_metadata": str(run_root / "run.json"),
        "normalized_output": str(run_root / "normalized" / "inventory.json"),
        "findings_output": str(run_root / "normalized" / "findings.json"),
        "profile": args.profile,
        "summary": normalized["summary"],
    }
    if report_output is not None:
        result["report_output"] = str(report_output)
    if defectdojo_output is not None:
        result["defectdojo_output"] = str(defectdojo_output)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
