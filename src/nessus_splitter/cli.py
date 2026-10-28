"""Command-line interface for nessus-splitter."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .splitter import MEBIBYTE, NessusSplitError, split_nessus


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _nonnegative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nessus-splitter",
        description=(
            "Split a .nessus export into smaller, independently valid Nessus "
            "XML files. ReportHost records are always kept intact."
        ),
    )
    parser.add_argument("input", type=Path, help="source .nessus file")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "-n",
        "--parts",
        type=_positive_int,
        help="create exactly this many non-empty output files",
    )
    mode.add_argument(
        "-s",
        "--size-mb",
        type=_positive_float,
        help="target size of each output file in MB (1 MB = 1024 x 1024 bytes)",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        help="output directory (default: <input-name>_split beside the input)",
    )
    parser.add_argument(
        "--grace-mb",
        type=_nonnegative_float,
        default=2.0,
        help="permitted size overshoot for --size-mb (default: 2 MB)",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace output files that already exist",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _format_size(byte_count: int) -> str:
    return f"{byte_count / MEBIBYTE:.2f} MB"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    output_dir = args.output_dir
    if output_dir is None:
        output_dir = args.input.parent / f"{args.input.stem}_split"

    try:
        results = split_nessus(
            args.input,
            output_dir=output_dir,
            parts=args.parts,
            size_mb=args.size_mb,
            grace_mb=args.grace_mb,
            force=args.force,
        )
    except NessusSplitError as exc:
        parser.exit(2, f"error: {exc}\n")

    total_hosts = sum(result.host_count for result in results)
    print(f"Created {len(results)} files containing {total_hosts} ReportHost records:")
    for result in results:
        suffix = " (over target + grace)" if result.over_size_limit else ""
        print(
            f"  {result.path} - {result.host_count} hosts, "
            f"{_format_size(result.size_bytes)}{suffix}"
        )

    oversized = [result for result in results if result.over_size_limit]
    if oversized:
        print(
            "warning: one or more files exceed the requested size tolerance "
            "because ReportHost records are never divided",
            file=sys.stderr,
        )

    return 0
