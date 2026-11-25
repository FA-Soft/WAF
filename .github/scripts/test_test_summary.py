#!/usr/bin/env python3
"""Tests of test_summary.py. Run: python -m unittest discover -s .github/scripts -p "test_*.py"."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import test_summary  # noqa: E402

NS = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"


def trx(assembly: str, results: list[tuple[str, str, str, str]], times: tuple[str, str] | None) -> str:
    """A TRX file: results are (name, duration, startTime, endTime); times is the run's (start, finish)."""
    times_xml = f'<Times creation="{times[0]}" start="{times[0]}" finish="{times[1]}" />' if times else ""
    rows = "".join(
        f'<UnitTestResult testName="{name}" outcome="Passed" testId="{i}" duration="{duration}"'
        + (f' startTime="{start}"' if start else "")
        + (f' endTime="{end}"' if end else "")
        + " />"
        for i, (name, duration, start, end) in enumerate(results)
    )
    definitions = "".join(
        f'<UnitTest name="{name}" storage="/src/{assembly}.dll" id="{i}" />' for i, (name, *_rest) in enumerate(results)
    )
    return f'<TestRun xmlns="{NS}">{times_xml}<Results>{rows}</Results><TestDefinitions>{definitions}</TestDefinitions></TestRun>'


class DurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._folder = tempfile.TemporaryDirectory()
        self.results = Path(self._folder.name)

    def tearDown(self) -> None:
        self._folder.cleanup()

    def write(self, name: str, content: str) -> None:
        (self.results / name).write_text(content, encoding="utf-8")

    def test_durations_are_elapsed_times_and_the_total_covers_overlapping_runs(self) -> None:
        # Unit tests: 10:00:00 to 10:04:00, but their test durations add up to 11 minutes (parallel).
        self.write("unit.trx", trx(
            "Waf.UnitTests",
            [(f"Unit{i}", "00:05:30.0000000", "", "") for i in range(2)],
            ("2026-11-25T10:00:00.1234567+00:00", "2026-11-25T10:04:00.1234567+00:00"),
        ))
        # Integration tests at the same time: 10:00:05 to 10:10:00.
        self.write("integration.trx", trx(
            "Waf.IntegrationTests",
            [("Integration", "00:15:00.0000000", "", "")],
            ("2026-11-25T10:00:05.0000000+00:00", "2026-11-25T10:10:00.0000000+00:00"),
        ))

        report, failures = test_summary.build_report(self.results, "Tests")

        self.assertEqual([], failures)
        self.assertIn("| Waf.UnitTests | 2 | 2 | 0 | 0 | 4m 0s |", report)
        self.assertIn("| Waf.IntegrationTests | 1 | 1 | 0 | 0 | 9m 55s |", report)
        self.assertIn("| **10m 0s** |", report)  # first start to last end, not 4m + 9m 55s
        self.assertNotIn("26m", report)  # not the sum of the test durations

    def test_without_run_times_the_first_test_start_and_last_test_end_are_used(self) -> None:
        self.write("unit.trx", trx(
            "Waf.UnitTests",
            [
                ("A", "00:00:02.0000000", "2026-11-25T10:00:00Z", "2026-11-25T10:00:02Z"),
                ("B", "00:00:03.0000000", "2026-11-25T10:00:01Z", "2026-11-25T10:00:04Z"),
                ("C", "00:00:01.0000000", "2026-11-25T10:00:05Z", ""),  # no end: start + duration
            ],
            None,
        ))

        assembly = test_summary.parse_trx(self.results / "unit.trx")

        self.assertEqual(timedelta(seconds=6), assembly.elapsed)

    def test_without_any_times_the_duration_is_unknown(self) -> None:
        self.write("unit.trx", trx("Waf.UnitTests", [("A", "00:00:02.0000000", "", "")], None))

        report, _ = test_summary.build_report(self.results, "Tests")

        self.assertIn("| Waf.UnitTests | 1 | 1 | 0 | 0 | — |", report)
        self.assertIn("| **—** |", report)

    def test_timestamps_with_seven_fraction_digits_and_offsets_are_read(self) -> None:
        later = test_summary.parse_time("2026-11-25T10:16:48.7852459+01:00")
        earlier = test_summary.parse_time("2026-11-25T09:16:48.0000000Z")
        assert later is not None and earlier is not None
        self.assertEqual(timedelta(seconds=0.785245), later - earlier)  # same hour in UTC; 7th digit dropped
        self.assertIsNone(test_summary.parse_time("not a time"))
        self.assertIsNone(test_summary.parse_time(None))

    def test_short_and_long_durations_are_formatted(self) -> None:
        self.assertEqual("0.4s", test_summary.format_duration(timedelta(seconds=0.355)))
        self.assertEqual("10m 57s", test_summary.format_duration(timedelta(minutes=10, seconds=57)))
        self.assertEqual("10m 0s", test_summary.format_duration(timedelta(seconds=599.9)))
        self.assertEqual("1m 0s", test_summary.format_duration(timedelta(seconds=59.97)))
        self.assertEqual("—", test_summary.format_duration(None))


if __name__ == "__main__":
    unittest.main()
