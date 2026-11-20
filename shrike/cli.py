"""Review a local Python project and write reports for developers and CI."""

import argparse
import csv
import html
import io
import json
import os
import stat
from dataclasses import asdict
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import quote

from shrike.checks import RULES, Finding, inspect


SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
IGNORED = {"node_modules", "vendor", "venv", "__pycache__", "build", "dist"}
MAX_BYTES = 1024 * 1024


def review(root: Path) -> tuple[list[Finding], list[dict[str, str]], int]:
    findings, issues = [], []
    analyzed = 0

    def walk_error(error):
        issues.append({"path": ".", "reason": type(error).__name__})

    for directory, folders, files in os.walk(root, onerror=walk_error):
        base = Path(directory)
        folders[:] = sorted(
            name for name in folders
            if not name.startswith(".") and name not in IGNORED
            and not (base / name).is_symlink() and not (base / name).is_junction()
        )
        for name in sorted(files):
            path = base / name
            if path.suffix != ".py" or name.startswith(".") or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            try:
                if not stat.S_ISREG(path.lstat().st_mode):
                    issues.append({"path": relative, "reason": "Not a regular file"})
                    continue
                with path.open("rb") as stream:
                    source = stream.read(MAX_BYTES + 1)
                if len(source) > MAX_BYTES:
                    issues.append({"path": relative, "reason": "File exceeds 1 MiB"})
                    continue
                findings.extend(inspect(source, relative))
                analyzed += 1
            except SyntaxError as error:
                issues.append({"path": relative, "reason": f"Parse error at line {error.lineno}"})
            except (OSError, ValueError, RecursionError) as error:
                issues.append({"path": relative, "reason": type(error).__name__})
    if not analyzed:
        issues.append({"path": ".", "reason": "No Python files analyzed"})
    return findings, issues, analyzed


def write_report(path: Path, content: str) -> None:
    temporary = None
    try:
        with NamedTemporaryFile(mode="w", dir=path.parent, encoding="utf-8",
                                newline="", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def export(output: Path, findings: list[Finding], issues: list[dict[str, str]], analyzed: int) -> None:
    if output.is_symlink() or output.is_junction():
        raise OSError("Report directory cannot be a symbolic link or junction")
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "status": "incomplete" if issues else "completed",
        "files_analyzed": analyzed,
        "issues": issues,
        "findings": [asdict(finding) for finding in findings],
    }
    write_report(output / "findings.json", json.dumps(report, indent=2) + "\n")
    csv_content = io.StringIO(newline="")
    writer = csv.writer(csv_content)
    writer.writerow(["rule", "severity", "file", "line", "title", "remediation"])
    for finding in findings:
        path = finding.path
        if path.lstrip().startswith(("=", "+", "-", "@")) or path.startswith(("\t", "\r", "\n")):
            path = "'" + path
        writer.writerow([finding.rule.id, finding.rule.severity, path, finding.line,
                         finding.rule.title, finding.rule.remediation])
    write_report(output / "findings.csv", csv_content.getvalue())

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Shrike", "rules": [
                {"id": rule.id, "shortDescription": {"text": rule.title},
                 "help": {"text": rule.remediation}} for rule in RULES.values()
            ]}},
            "invocations": [{"executionSuccessful": not issues}],
            "results": [{
                "ruleId": finding.rule.id, "level": "warning",
                "message": {"text": finding.rule.title},
                "partialFingerprints": {"shrikeAst/v1": finding.fingerprint},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.path, safe="/")},
                    "region": {"startLine": finding.line},
                }}],
            } for finding in findings],
        }],
    }
    write_report(output / "findings.sarif", json.dumps(sarif, indent=2) + "\n")
    rows = [
        f"{finding.rule.id} · {finding.rule.severity} · {finding.path}:{finding.line} — "
        f"{finding.rule.title}. {finding.rule.remediation}" for finding in findings
    ]
    rows.extend(f"Coverage issue: {issue['path']} — {issue['reason']}" for issue in issues)
    summary = f"{analyzed} files analyzed · {len(findings)} findings · {report['status']}"
    items = "".join(f"<li>{html.escape(row)}</li>" for row in rows)
    write_report(
        output / "index.html",
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Shrike review</title><style>body{font:1rem/1.6 system-ui;max-width:58rem;'
        'margin:3rem auto;padding:0 1rem;background:#101828;color:#f0f4ff}'
        'li{padding:0.7rem 0;border-bottom:1px solid #475467}</style>'
        f'<main><h1>Shrike source review</h1><p>{summary}</p><ul>{items}</ul></main></html>',
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Local Python project directory")
    parser.add_argument("--output", type=Path, default=Path(".shrike"))
    parser.add_argument("--fail-on", choices=SEVERITY, default="high")
    args = parser.parse_args(argv)
    raw_target = args.target
    if raw_target.startswith(("//", "\\\\")) or "://" in raw_target:
        parser.error("--target must be a local directory")
    target = Path(raw_target)
    if not target.is_dir() or target.is_symlink() or target.is_junction():
        parser.error("--target must be a local directory")
    try:
        findings, issues, analyzed = review(target.resolve())
        export(args.output, findings, issues, analyzed)
    except OSError as error:
        parser.exit(1, f"Shrike could not write its reports: {error}\n")
    print(f"Analyzed {analyzed} files and found {len(findings)} review items. Reports: {args.output}")
    if issues:
        return 1
    return 2 if any(SEVERITY[item.rule.severity] >= SEVERITY[args.fail_on] for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
