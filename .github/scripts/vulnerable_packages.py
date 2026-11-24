"""Reports known vulnerabilities in NuGet packages (direct and transitive) and fails on high or critical ones.

Input: the JSON of `dotnet list <solution> package --vulnerable --include-transitive --format json`.
Writes a Markdown table to the GitHub step summary (GITHUB_STEP_SUMMARY) and an annotation per finding.
Exit code 1 when a package has a High or Critical advisory, 0 otherwise.

    python .github/scripts/vulnerable_packages.py vulnerable.json
"""

import json
import os
import sys

FAILING = {"high", "critical"}


def findings(report):
    for project in report.get("projects", []):
        name = os.path.basename(project.get("path", "?"))
        for framework in project.get("frameworks", []):
            for kind, key in (("direct", "topLevelPackages"), ("transitive", "transitivePackages")):
                for package in framework.get(key, []):
                    for advisory in package.get("vulnerabilities", []):
                        yield {
                            "project": name,
                            "package": package.get("id", "?"),
                            "version": package.get("resolvedVersion", "?"),
                            "kind": kind,
                            "severity": advisory.get("severity", "?"),
                            "url": advisory.get("advisoryurl", ""),
                        }


def main(path):
    with open(path, encoding="utf-8-sig") as file:
        report = json.load(file)

    rows = sorted({tuple(f.items()) for f in findings(report)})
    rows = [dict(r) for r in rows]
    lines = ["## Dependency scan", ""]
    if not rows:
        lines.append("No known vulnerabilities in direct or transitive NuGet packages.")
    else:
        lines += ["| Severity | Package | Version | | Project | Advisory |", "|---|---|---|---|---|---|"]
        for f in rows:
            lines.append(f"| {f['severity']} | {f['package']} | {f['version']} | {f['kind']} | {f['project']} | {f['url']} |")
            level = "error" if f["severity"].lower() in FAILING else "warning"
            print(f"::{level}::{f['severity']} vulnerability in {f['package']} {f['version']} ({f['kind']}, {f['project']}): {f['url']}")

    text = "\n".join(lines) + "\n"
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as file:
            file.write(text)

    return 1 if any(f["severity"].lower() in FAILING for f in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
