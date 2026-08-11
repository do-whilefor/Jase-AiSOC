"""Emit the local Linux capability report for installation and support diagnostics."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from aisoc.platform.linux import LinuxPlatformAdapter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisoc-probe-platform",
        description="Print a read-only Linux platform and collector capability report.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="indent the JSON output for interactive diagnostics",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    report = LinuxPlatformAdapter().capabilities()
    json.dump(
        report.model_dump(mode="json"),
        sys.stdout,
        ensure_ascii=False,
        indent=2 if arguments.pretty else None,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
