#!/usr/bin/env python3
"""CLI for ELF/shared-object static analysis implemented through Milestone 4."""

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
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    args = parser.parse_args()
    try:
        run_root, normalized = scan(args.target, args.output_dir)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        "run_id": normalized["run_id"],
        "run_root": str(run_root),
        "normalized_output": str(run_root / "normalized" / "inventory.json"),
        "summary": normalized["summary"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
