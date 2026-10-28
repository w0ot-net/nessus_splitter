from __future__ import annotations

import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from nessus_splitter import NessusSplitError, split_nessus


def write_fixture(path: Path, host_payload_sizes: list[int]) -> None:
    root = ET.Element("NessusClientData_v2")
    policy = ET.SubElement(root, "Policy")
    ET.SubElement(policy, "policyName").text = "Test Policy"
    report = ET.SubElement(root, "Report", {"name": "Test Report"})
    for index, payload_size in enumerate(host_payload_sizes, start=1):
        host = ET.SubElement(report, "ReportHost", {"name": f"192.0.2.{index}"})
        properties = ET.SubElement(host, "HostProperties")
        ET.SubElement(properties, "tag", {"name": "host-ip"}).text = f"192.0.2.{index}"
        item = ET.SubElement(
            host,
            "ReportItem",
            {"port": "443", "protocol": "tcp", "pluginID": str(index)},
        )
        ET.SubElement(item, "plugin_name").text = "Example <check> & test"
        ET.SubElement(item, "plugin_output").text = "x" * payload_size
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def read_hosts(path: Path) -> list[str]:
    root = ET.parse(path).getroot()
    report = root.find("Report")
    assert report is not None
    return [host.get("name", "") for host in report.findall("ReportHost")]


def serialized_hosts(path: Path) -> list[bytes]:
    root = ET.parse(path).getroot()
    report = root.find("Report")
    assert report is not None
    serialized = []
    for host in report.findall("ReportHost"):
        host.tail = None
        serialized.append(ET.tostring(host, encoding="utf-8"))
    return serialized


class SplitNessusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_exact_parts_are_valid_balanced_and_ordered(self) -> None:
        source = self.root / "scan.nessus"
        write_fixture(source, [200, 2_000, 500, 3_000, 700, 1_500])

        results = split_nessus(source, output_dir=self.root / "out", parts=3)

        self.assertEqual([result.path.name for result in results], [
            "scan_01.nessus",
            "scan_02.nessus",
            "scan_03.nessus",
        ])
        self.assertEqual(sum(result.host_count for result in results), 6)
        hosts = [host for result in results for host in read_hosts(result.path)]
        self.assertEqual(hosts, [f"192.0.2.{index}" for index in range(1, 7)])
        output_host_xml = [
            host_xml
            for result in results
            for host_xml in serialized_hosts(result.path)
        ]
        self.assertEqual(output_host_xml, serialized_hosts(source))
        for result in results:
            parsed = ET.parse(result.path).getroot()
            self.assertEqual(parsed.findtext("Policy/policyName"), "Test Policy")
            self.assertEqual(parsed.find("Report").get("name"), "Test Report")

    def test_part_number_padding_expands_for_large_counts(self) -> None:
        source = self.root / "many.nessus"
        write_fixture(source, [10] * 100)

        results = split_nessus(source, output_dir=self.root / "out", parts=100)

        self.assertEqual(results[0].path.name, "many_001.nessus")
        self.assertEqual(results[-1].path.name, "many_100.nessus")

    def test_size_mode_creates_multiple_files_and_preserves_hosts(self) -> None:
        source = self.root / "sized.nessus"
        write_fixture(source, [4_000] * 8)

        results = split_nessus(
            source,
            output_dir=self.root / "out",
            size_mb=0.012,
            grace_mb=0.002,
        )

        self.assertGreater(len(results), 1)
        self.assertEqual(sum(result.host_count for result in results), 8)
        hosts = [host for result in results for host in read_hosts(result.path)]
        self.assertEqual(hosts, [f"192.0.2.{index}" for index in range(1, 9)])
        self.assertFalse(any(result.over_size_limit for result in results))

    def test_oversized_single_host_is_kept_intact_and_flagged(self) -> None:
        source = self.root / "oversized.nessus"
        write_fixture(source, [30_000, 500])

        results = split_nessus(
            source,
            output_dir=self.root / "out",
            size_mb=0.01,
            grace_mb=0,
        )

        self.assertTrue(results[0].over_size_limit)
        self.assertEqual(sum(result.host_count for result in results), 2)

    def test_rejects_more_parts_than_hosts(self) -> None:
        source = self.root / "small.nessus"
        write_fixture(source, [100, 100])

        with self.assertRaisesRegex(NessusSplitError, "non-empty files"):
            split_nessus(source, output_dir=self.root / "out", parts=3)

    def test_does_not_replace_existing_outputs_without_force(self) -> None:
        source = self.root / "existing.nessus"
        output_dir = self.root / "out"
        write_fixture(source, [100, 100])
        first = split_nessus(source, output_dir=output_dir, parts=2)
        original = first[0].path.read_bytes()

        with self.assertRaisesRegex(NessusSplitError, "--force"):
            split_nessus(source, output_dir=output_dir, parts=2)

        self.assertEqual(first[0].path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
