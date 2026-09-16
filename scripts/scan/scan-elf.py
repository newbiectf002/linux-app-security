#!/usr/bin/env python3
"""Run static ELF/shared-object inventory and finding correlation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from elf_inventory import scan  # noqa: E402


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
    args = parser.parse_args()
    try:
        run_root, normalized = scan(args.target, args.output_dir, target_root=args.target_root)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.target.is_file() and normalized["summary"]["unsupported"] == 1:
        parser.error(
            f"unsupported input (expected an ELF executable or shared object): {args.target}; "
            f"inspection evidence retained at {run_root}"
        )
    print(json.dumps({
        "run_id": normalized["run_id"],
        "run_root": str(run_root),
        "run_metadata": str(run_root / "run.json"),
        "normalized_output": str(run_root / "normalized" / "inventory.json"),
        "findings_output": str(run_root / "normalized" / "findings.json"),
        "summary": normalized["summary"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
