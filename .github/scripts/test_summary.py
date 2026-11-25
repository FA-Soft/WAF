#!/usr/bin/env python3
"""Write a Markdown test summary for the GitHub Actions job summary page.

Reads the TRX files (test results) and Cobertura files (code coverage) that
`dotnet test --report-xunit-trx --coverage --coverage-output-format cobertura`
writes into a results directory, and appends a Markdown report to the file in
$GITHUB_STEP_SUMMARY (or prints it when that variable is not set).

Failed tests are also emitted as GitHub error annotations, so they show up on
the run page and in pull request checks.

Usage: test_summary.py <results-directory> <title>
Uses only the Python standard library. Always exits 0: failing the build is
the test step's job, this script only reports.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
import re
from datetime import datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree

TRX_NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}
MAX_LISTED = 50          # cap on failed/skipped tests listed in the summary
MAX_STACK_LINES = 15


@dataclass
class TestCase:
    name: str
    outcome: str
    message: str = ""
    stack: str = ""


@dataclass
class Assembly:
    name: str
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    start: datetime | None = None   # when the test run started (wall clock)
    finish: datetime | None = None  # when it finished
    failures: list[TestCase] = field(default_factory=list)
    skips: list[TestCase] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.skipped

    @property
    def elapsed(self) -> timedelta | None:
        """Wall-clock time of the run. Not the sum of the test durations: tests run in parallel."""
        if self.start is None or self.finish is None:
            return None
        return max(self.finish - self.start, timedelta())


def parse_duration(text: str | None) -> timedelta:
    """Parse a TRX duration such as '00:00:01.2340000'."""
    if not text:
        return timedelta()
    try:
        hours, minutes, seconds = text.split(":")
        return timedelta(hours=int(hours), minutes=int(minutes), seconds=float(seconds))
    except ValueError:
        return timedelta()


_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_time(text: str | None) -> datetime | None:
    """Parse a TRX timestamp such as '2026-11-25T10:16:48.7852459+00:00' (7 fraction digits, an offset or Z)."""
    if not text:
        return None
    text = _FRACTION.sub(r"\1", text.strip()).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def text_of(element: ElementTree.Element | None, path: str) -> str:
    found = element.find(path, TRX_NS) if element is not None else None
    return (found.text or "").strip() if found is not None else ""


def parse_trx(path: Path) -> Assembly:
    root = ElementTree.parse(path).getroot()

    # Map test id -> assembly file name using the test definitions.
    assembly_names: dict[str, str] = {}
    for test in root.iterfind("t:TestDefinitions/t:UnitTest", TRX_NS):
        storage = test.get("storage") or ""
        assembly_names[test.get("id", "")] = Path(storage.replace("\\", "/")).stem or "Tests"

    name = next(iter(assembly_names.values()), path.stem)
    assembly = Assembly(name=name)

    # The run's own start and finish; without them, the first test's start and the last test's end.
    times = root.find("t:Times", TRX_NS)
    if times is not None:
        assembly.start = parse_time(times.get("start"))
        assembly.finish = parse_time(times.get("finish"))
    starts: list[datetime] = []
    ends: list[datetime] = []

    for result in root.iterfind("t:Results/t:UnitTestResult", TRX_NS):
        outcome = result.get("outcome", "")
        if (started := parse_time(result.get("startTime"))) is not None:
            starts.append(started)
        if (ended := parse_time(result.get("endTime"))) is not None:
            ends.append(ended)
        elif started is not None:
            ends.append(started + parse_duration(result.get("duration")))
        case = TestCase(
            name=result.get("testName", "(unnamed)"),
            outcome=outcome,
            message=text_of(result, "t:Output/t:ErrorInfo/t:Message") or text_of(result, "t:Output/t:StdOut"),
            stack=text_of(result, "t:Output/t:ErrorInfo/t:StackTrace"),
        )
        if outcome == "Passed":
            assembly.passed += 1
        elif outcome in ("Failed", "Error", "Timeout", "Aborted"):
            assembly.failed += 1
            assembly.failures.append(case)
        else:  # NotExecuted, Inconclusive, ...
            assembly.skipped += 1
            assembly.skips.append(case)

    if assembly.start is None and starts:
        assembly.start = min(starts)
    if assembly.finish is None and ends:
        assembly.finish = max(ends)
    return assembly


def total_elapsed(assemblies: list[Assembly]) -> timedelta | None:
    """From the earliest start to the latest finish: the assemblies run at the same time, so their times overlap."""
    starts = [a.start for a in assemblies if a.start is not None]
    finishes = [a.finish for a in assemblies if a.finish is not None]
    if not starts or not finishes or any(a.elapsed is None for a in assemblies):
        return None
    return max(max(finishes) - min(starts), timedelta())


def find_coverage(results: Path) -> Path | None:
    merged = sorted(results.glob("merged/*.cobertura.xml"))
    if merged:
        return merged[0]
    files = sorted(results.rglob("*.cobertura.xml"))
    return files[0] if len(files) == 1 else None


def coverage_section(path: Path) -> list[str]:
    root = ElementTree.parse(path).getroot()

    def pct(rate: str | None) -> str:
        return f"{float(rate or 0) * 100:.1f}%"

    lines = [
        "#### Code coverage",
        "",
        "| Package | Line | Branch |",
        "|---|---:|---:|",
    ]
    for package in sorted(root.iterfind("packages/package"), key=lambda p: p.get("name", "")):
        lines.append(f"| {package.get('name')} | {pct(package.get('line-rate'))} | {pct(package.get('branch-rate'))} |")
    lines.append(
        f"| **Total** | **{pct(root.get('line-rate'))}** ({root.get('lines-covered')}/{root.get('lines-valid')}) "
        f"| **{pct(root.get('branch-rate'))}** ({root.get('branches-covered')}/{root.get('branches-valid')}) |"
    )
    lines.append("")
    return lines


def format_duration(value: timedelta | None) -> str:
    if value is None:
        return "—"
    seconds = value.total_seconds()
    if seconds < 59.95:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(round(seconds), 60)  # round first, so 599.9 s is 10m 0s, not 9m 60s
    return f"{minutes}m {rest}s"


def escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def annotation_escape(text: str) -> str:
    """Escape the message part of a GitHub workflow command."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotation_property_escape(text: str) -> str:
    """Escape a property value (e.g. title) of a GitHub workflow command."""
    return annotation_escape(text).replace(":", "%3A").replace(",", "%2C")


def build_report(results: Path, title: str) -> tuple[str, list[TestCase]]:
    trx_files = sorted(results.rglob("*.trx"))
    if not trx_files:
        return f"### ⚠️ {title}\n\nNo test results (TRX files) found in `{results}`.\n", []

    assemblies = sorted((parse_trx(p) for p in trx_files), key=lambda a: a.name)
    failed = sum(a.failed for a in assemblies)
    icon = "❌" if failed else "✅"

    lines = [
        f"### {icon} {title}",
        "",
        "| Test assembly | Total | ✅ Passed | ❌ Failed | ⏭️ Skipped | Duration |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for a in assemblies:
        lines.append(f"| {a.name} | {a.total} | {a.passed} | {a.failed} | {a.skipped} | {format_duration(a.elapsed)} |")
    lines.append(
        f"| **Total** | **{sum(a.total for a in assemblies)}** | **{sum(a.passed for a in assemblies)}** "
        f"| **{failed}** | **{sum(a.skipped for a in assemblies)}** "
        f"| **{format_duration(total_elapsed(assemblies))}** |"
    )
    lines += [
        "",
        "<sub>Duration: elapsed time of each test run, from its start to its end. Tests run in parallel and the "
        "assemblies at the same time, so the total runs from the first start to the last end, not the sum of the rows.</sub>",
        "",
    ]

    failures = [f for a in assemblies for f in a.failures]
    if failures:
        lines += ["#### Failed tests", ""]
        for case in failures[:MAX_LISTED]:
            stack = "\n".join(case.stack.splitlines()[:MAX_STACK_LINES])
            lines += [
                f"<details><summary>❌ <code>{case.name}</code></summary>",
                "",
                "```text",
                case.message or "(no message)",
                *( ["", stack] if stack else [] ),
                "```",
                "",
                "</details>",
                "",
            ]
        if len(failures) > MAX_LISTED:
            lines += [f"…and {len(failures) - MAX_LISTED} more.", ""]

    skips = [s for a in assemblies for s in a.skips]
    if skips:
        lines += [
            f"<details><summary>⏭️ Skipped tests ({len(skips)})</summary>",
            "",
            "| Test | Reason |",
            "|---|---|",
        ]
        lines += [f"| `{s.name}` | {escape_cell(s.message) or '—'} |" for s in skips[:MAX_LISTED]]
        lines += ["", "</details>", ""]

    coverage = find_coverage(results)
    if coverage is not None:
        lines += coverage_section(coverage)

    return "\n".join(lines) + "\n", failures


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 0

    results, title = Path(sys.argv[1]), sys.argv[2]
    try:
        report, failures = build_report(results, title) if results.is_dir() else (
            f"### ⚠️ {title}\n\nResults directory `{results}` does not exist.\n", [])
    except ElementTree.ParseError as error:
        report, failures = f"### ⚠️ {title}\n\nCould not parse test results: {error}\n", []

    for case in failures:
        print(f"::error title={annotation_property_escape('Test failed: ' + case.name)}::{annotation_escape(case.message or 'Test failed')}")

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as handle:
            handle.write(report)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
