"""Streaming Nessus XML inspection, partition planning, and output writing."""

from __future__ import annotations

import os
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

MEBIBYTE = 1024 * 1024
XML_DECLARATION = b'<?xml version="1.0" encoding="UTF-8"?>\n'
WRAPPER_MARKER = "__NESSUS_SPLITTER_CONTENT_18CBA40A__"


class NessusSplitError(Exception):
    """Raised when a Nessus export cannot be split safely."""


@dataclass(frozen=True)
class NessusLayout:
    """Reusable document framing and serialized ReportHost sizes."""

    header: bytes
    footer: bytes
    host_sizes: tuple[int, ...]

    @property
    def overhead_size(self) -> int:
        return len(self.header) + len(self.footer)


@dataclass(frozen=True)
class PartResult:
    """Details about one generated output file."""

    path: Path
    host_count: int
    size_bytes: int
    over_size_limit: bool = False


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _register_namespace(prefix: str, uri: str) -> None:
    try:
        ET.register_namespace(prefix, uri)
    except ValueError:
        # ElementTree reserves prefixes such as ns0. Its generated prefix still
        # produces valid XML, so an unsupported original prefix is non-fatal.
        pass


def _serialize_element(element: ET.Element) -> bytes:
    """Serialize an element without inherited indentation from its old parent."""
    original_tail = element.tail
    element.tail = None
    try:
        return ET.tostring(element, encoding="utf-8") + b"\n"
    finally:
        element.tail = original_tail


def _wrapper_bytes(tag: str, attributes: dict[str, str]) -> tuple[bytes, bytes]:
    """Return the opening and closing bytes for an XML element."""
    wrapper = ET.Element(tag, attributes)
    wrapper.text = WRAPPER_MARKER
    serialized = ET.tostring(wrapper, encoding="utf-8")
    marker = WRAPPER_MARKER.encode("ascii")
    opening, found, closing = serialized.partition(marker)
    if not found:
        raise NessusSplitError(f"failed to serialize XML wrapper {tag!r}")
    return opening, closing


def inspect_nessus(path: Path) -> NessusLayout:
    """Inspect a Nessus export without retaining all ReportHost data in memory."""
    root: ET.Element | None = None
    report: ET.Element | None = None
    stack: list[ET.Element] = []
    root_open = root_close = report_open = report_close = None
    root_before: list[bytes] = []
    root_after: list[bytes] = []
    report_before: list[bytes] = []
    report_after: list[bytes] = []
    host_sizes: list[int] = []
    report_found = False
    report_complete = False
    host_found = False

    try:
        events = ET.iterparse(path, events=("start", "end", "start-ns"))
        for event, value in events:
            if event == "start-ns":
                prefix, uri = value
                _register_namespace(prefix, uri)
                continue

            element = value
            if event == "start":
                stack.append(element)
                if len(stack) == 1:
                    root = element
                    if _local_name(root.tag) != "NessusClientData_v2":
                        raise NessusSplitError(
                            "input root element is not NessusClientData_v2"
                        )
                    root_open, root_close = _wrapper_bytes(root.tag, dict(root.attrib))
                elif (
                    len(stack) == 2
                    and stack[-2] is root
                    and _local_name(element.tag) == "Report"
                ):
                    if report_found:
                        raise NessusSplitError("multiple Report elements are not supported")
                    report_found = True
                    report = element
                    report_open, report_close = _wrapper_bytes(
                        report.tag, dict(report.attrib)
                    )
                continue

            parent = stack[-2] if len(stack) > 1 else None
            if report is not None and parent is report:
                if _local_name(element.tag) == "ReportHost":
                    host_chunk = _serialize_element(element)
                    host_sizes.append(len(host_chunk))
                    host_found = True
                else:
                    destination = report_after if host_found else report_before
                    destination.append(_serialize_element(element))
                report.remove(element)
                element.clear()
            elif root is not None and parent is root:
                if element is report:
                    report_complete = True
                    root.remove(element)
                    element.clear()
                    report = None
                else:
                    destination = root_after if report_complete else root_before
                    destination.append(_serialize_element(element))
                    root.remove(element)
                    element.clear()

            stack.pop()
    except (ET.ParseError, OSError) as exc:
        raise NessusSplitError(f"could not parse {path}: {exc}") from exc

    if not report_found or report_open is None or report_close is None:
        raise NessusSplitError("input does not contain a Report element")
    if root_open is None or root_close is None:
        raise NessusSplitError("input does not contain a valid root element")
    if not host_sizes:
        raise NessusSplitError("input does not contain any ReportHost records")

    header = b"".join(
        (
            XML_DECLARATION,
            root_open,
            b"\n",
            *root_before,
            report_open,
            b"\n",
            *report_before,
        )
    )
    footer = b"".join(
        (
            *report_after,
            report_close,
            b"\n",
            *root_after,
            root_close,
            b"\n",
        )
    )
    return NessusLayout(header, footer, tuple(host_sizes))


def _iter_host_chunks(path: Path) -> Iterator[bytes]:
    stack: list[ET.Element] = []
    try:
        events = ET.iterparse(path, events=("start", "end", "start-ns"))
        for event, value in events:
            if event == "start-ns":
                prefix, uri = value
                _register_namespace(prefix, uri)
                continue

            element = value
            if event == "start":
                stack.append(element)
                continue

            parent = stack[-2] if len(stack) > 1 else None
            is_report_host = (
                parent is not None
                and _local_name(parent.tag) == "Report"
                and _local_name(element.tag) == "ReportHost"
            )
            if is_report_host:
                chunk = _serialize_element(element)
                parent.remove(element)
                element.clear()
                stack.pop()
                yield chunk
                continue

            stack.pop()
    except (ET.ParseError, OSError) as exc:
        raise NessusSplitError(f"could not read ReportHost records from {path}: {exc}") from exc


def _plan_by_parts(host_sizes: Sequence[int], parts: int) -> list[int]:
    if parts > len(host_sizes):
        raise NessusSplitError(
            f"cannot create {parts} non-empty files from {len(host_sizes)} ReportHost records"
        )

    counts: list[int] = []
    cursor = 0
    remaining_size = sum(host_sizes)

    for part_index in range(parts):
        parts_left = parts - part_index
        hosts_left = len(host_sizes) - cursor
        if parts_left == 1:
            take = hosts_left
            consumed = sum(host_sizes[cursor:])
        else:
            target = remaining_size / parts_left
            max_take = hosts_left - (parts_left - 1)
            take = 0
            consumed = 0
            while take < max_take:
                next_size = host_sizes[cursor + take]
                if take > 0 and abs(consumed - target) <= abs(
                    consumed + next_size - target
                ):
                    break
                consumed += next_size
                take += 1

        counts.append(take)
        cursor += take
        remaining_size -= consumed

    return counts


def _plan_by_size(
    host_sizes: Sequence[int],
    overhead_size: int,
    target_size: int,
    grace_size: int,
) -> list[int]:
    if target_size <= overhead_size:
        raise NessusSplitError(
            "requested size is smaller than the repeated Nessus policy/report metadata "
            f"({overhead_size / MEBIBYTE:.2f} MB)"
        )

    upper_limit = target_size + grace_size
    counts: list[int] = []
    current_count = 0
    current_payload = 0

    for host_size in host_sizes:
        if current_count == 0:
            current_count = 1
            current_payload = host_size
            continue

        before_size = overhead_size + current_payload
        after_size = before_size + host_size
        if after_size <= target_size:
            current_count += 1
            current_payload += host_size
            continue

        add_crossing_host = (
            after_size <= upper_limit
            and abs(after_size - target_size) < abs(before_size - target_size)
        )
        if add_crossing_host:
            current_count += 1
            current_payload += host_size

        counts.append(current_count)
        if add_crossing_host:
            current_count = 0
            current_payload = 0
        else:
            current_count = 1
            current_payload = host_size

    if current_count:
        counts.append(current_count)
    return counts


def _validate_output(path: Path, expected_hosts: int) -> None:
    host_count = 0
    root_name = None
    report_count = 0
    stack: list[ET.Element] = []
    try:
        for event, element in ET.iterparse(path, events=("start", "end")):
            if event == "start":
                stack.append(element)
                if root_name is None:
                    root_name = _local_name(element.tag)
                if _local_name(element.tag) == "Report":
                    report_count += 1
                continue

            if _local_name(element.tag) == "ReportHost":
                host_count += 1
            if len(stack) > 1:
                parent = stack[-2]
                parent.remove(element)
            element.clear()
            stack.pop()
    except (ET.ParseError, OSError) as exc:
        raise NessusSplitError(f"generated file failed XML validation: {path}: {exc}") from exc

    if root_name != "NessusClientData_v2":
        raise NessusSplitError(f"generated file has an invalid root element: {path}")
    if report_count != 1:
        raise NessusSplitError(f"generated file does not contain exactly one Report: {path}")
    if host_count != expected_hosts:
        raise NessusSplitError(
            f"generated file contains {host_count} hosts instead of {expected_hosts}: {path}"
        )


def split_nessus(
    input_path: str | Path,
    *,
    output_dir: str | Path,
    parts: int | None = None,
    size_mb: float | None = None,
    grace_mb: float = 2.0,
    force: bool = False,
) -> list[PartResult]:
    """Split one Nessus export and return details for the generated files."""
    source = Path(input_path).expanduser().resolve()
    destination = Path(output_dir).expanduser().resolve()

    if not source.is_file():
        raise NessusSplitError(f"input file does not exist: {source}")
    if source.suffix.lower() != ".nessus":
        raise NessusSplitError("input file must use the .nessus extension")
    if (parts is None) == (size_mb is None):
        raise NessusSplitError("specify exactly one of parts or size_mb")
    if parts is not None and parts < 1:
        raise NessusSplitError("parts must be at least 1")
    if size_mb is not None and size_mb <= 0:
        raise NessusSplitError("size_mb must be greater than 0")
    if grace_mb < 0:
        raise NessusSplitError("grace_mb must be 0 or greater")

    layout = inspect_nessus(source)
    target_size = None
    upper_limit = None
    if parts is not None:
        host_counts = _plan_by_parts(layout.host_sizes, parts)
    else:
        target_size = round(size_mb * MEBIBYTE)
        grace_size = round(grace_mb * MEBIBYTE)
        upper_limit = target_size + grace_size
        host_counts = _plan_by_size(
            layout.host_sizes,
            layout.overhead_size,
            target_size,
            grace_size,
        )

    width = max(2, len(str(len(host_counts))))
    output_paths = [
        destination / f"{source.stem}_{index:0{width}d}.nessus"
        for index in range(1, len(host_counts) + 1)
    ]
    existing = [path for path in output_paths if path.exists()]
    if existing and not force:
        preview = ", ".join(str(path) for path in existing[:3])
        if len(existing) > 3:
            preview += f", and {len(existing) - 3} more"
        raise NessusSplitError(f"output files already exist: {preview}; use --force")

    destination.mkdir(parents=True, exist_ok=True)
    temporary_paths: list[Path] = []
    pending_results: list[tuple[Path, Path, int, int, bool]] = []
    host_chunks = _iter_host_chunks(source)

    try:
        for output_path, expected_hosts in zip(output_paths, host_counts):
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination,
                prefix=f".{output_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as output:
                temporary_path = Path(output.name)
                temporary_paths.append(temporary_path)
                output.write(layout.header)
                for _ in range(expected_hosts):
                    try:
                        output.write(next(host_chunks))
                    except StopIteration as exc:
                        raise NessusSplitError(
                            "input changed while it was being split"
                        ) from exc
                output.write(layout.footer)

            _validate_output(temporary_path, expected_hosts)
            size_bytes = temporary_path.stat().st_size
            over_limit = upper_limit is not None and size_bytes > upper_limit
            pending_results.append(
                (
                    temporary_path,
                    output_path,
                    expected_hosts,
                    size_bytes,
                    over_limit,
                )
            )

        try:
            next(host_chunks)
        except StopIteration:
            pass
        else:
            raise NessusSplitError("input changed while it was being split")

        results: list[PartResult] = []
        for temporary_path, output_path, host_count, size_bytes, over_limit in pending_results:
            os.chmod(temporary_path, 0o644)
            os.replace(temporary_path, output_path)
            temporary_paths.remove(temporary_path)
            results.append(
                PartResult(output_path, host_count, size_bytes, over_limit)
            )
        return results
    finally:
        for temporary_path in temporary_paths:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
