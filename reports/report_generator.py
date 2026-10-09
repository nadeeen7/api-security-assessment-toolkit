"""Escaped HTML/Markdown and structured JSON evidence; no raw bodies."""
import json
from pathlib import Path
from collections import Counter
from jinja2 import Environment, FileSystemLoader, select_autoescape
from core.risk_engine import SEVERITIES

def md(value):
    text = str(value).replace("\r", " ").replace("\n", " ")
    # Escape HTML and Markdown syntax in all untrusted strings.
    import html
    text = html.escape(text)
    for char in "\\`*_{}[]()#+-.!|>":
        text = text.replace(char, "\\" + char)
    return text

def generate(report, output):
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    counts = Counter(f["severity"] for f in report["findings"])
    report["severity_summary"] = {s: counts[s] for s in SEVERITIES}
    environment = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                              autoescape=select_autoescape(["html"]))
    (directory / "report.html").write_text(environment.get_template("report.html").render(report=report), encoding="utf-8")
    lines = ["# API Security Assessment", "", "Target: " + md(report["target"]),
             "", "Assessment date: " + md(report["date"]), "", "## Scope", md(report["scope"]),
             "", "## Methodology", md(report["methodology"]), "", "## Severity summary", "",
             "| Severity | Count |", "|---|---:|"]
    lines += [f"| {s} | {count} |" for s, count in report["severity_summary"].items()]
    lines += ["", "## Endpoint summary", "", "| Method | Endpoint | Actual Status | Authentication | Result / Note |", "|---|---|---|---|---|"]
    for e in report["endpoints"]:
        path_display = e["path"] + (f" (example: {e['resolved_path']})" if e.get("resolved_path") and e.get("resolved_path") != e["path"] else "")
        actual = e.get("actual_status")
        status_display = f"HTTP {actual}" if actual is not None else "Not observed"
        auth_display = (e.get("authentication") or "—") + (f" (Auth: {e['authenticated']})" if e.get("authenticated") and e.get("authenticated") not in ("Skipped", "No") else "")
        result_display = (f"[{e['check_status'].upper()}] " if e.get("check_status") else "") + (e.get("check_reason") or "—")
        lines.append("| " + " | ".join(md(val) for val in (e["method"], path_display, status_display, auth_display, result_display)) + " |")
    lines += ["", "## Findings"]
    if not report["findings"]:
        lines += ["No findings generated. This is not a security certification."]
    for number, f in enumerate(report["findings"], 1):
        lines += ["", f"### {number}. " + md(f["title"]), "",
            "Severity: " + md(f["severity"]) + " | Confidence: " + md(f["confidence"]), "",
            "Classification: " + md(f["classification"]), "", "Category: " + md(f["category"]), "",
            "Endpoint: " + md(f["method"] + " " + f["endpoint"]), "",
            md(f["description"]), "", "Severity rationale: " + md(f["severity_reason"]), "",
            "Evidence: " + md(json.dumps(f["evidence"], ensure_ascii=True)), "",
            "Recommendation: " + md(f["recommendation"]), "",
            "References: " + md(str(f["cwe"] or "Not assigned") + "; " + str(f["owasp_api"] or "Not assigned"))]
    lines += ["", "## Test coverage", "",
              "A selected test is never reported as executed unless it actually ran.", "",
              "| Test | Status | Findings | Reason / note |", "|---|---|---:|---|"]
    for t in (report["coverage"].get("tests") or []):
        lines.append("| " + " | ".join(md(str(t.get(key, ""))) for key in ("key", "status", "findings", "reason")) + " |")
    for name in ("coverage", "metadata", "limitations"):
        lines += ["", "## " + name.title(), "", md(json.dumps(report[name], ensure_ascii=True))]
    (directory / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (directory / "evidence.json").write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    return [directory / name for name in ("report.html", "report.md", "evidence.json")]
