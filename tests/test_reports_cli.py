import json
from pathlib import Path
from main import main, parser, run
from reports.report_generator import generate

ROOT = Path(__file__).resolve().parents[1]

def test_cli_offline_reports_and_query_redaction(tmp_path):
    endpoints = tmp_path / "endpoints.json"
    endpoints.write_text('["/api/search?token=do-not-save"]')
    output = tmp_path / "report"
    assert main(["--openapi", str(ROOT / "input/openapi.json"), "--endpoints", str(endpoints), "--output", str(output)]) == 0
    for path in output.iterdir():
        assert "do-not-save" not in path.read_text()
    assert json.loads((output / "evidence.json").read_text())["coverage"]["requests_sent"] == 0

def test_report_escaping(tmp_path):
    text = '<script>alert(1)</script>[click](https://evil.test)'
    report = {"target":text,"date":"test","scope":text,"methodology":text,"findings":[],"endpoints":[],"coverage":{},"metadata":{},"limitations":[text]}
    generate(report, tmp_path)
    html = (tmp_path / "report.html").read_text()
    md = (tmp_path / "report.md").read_text()
    assert "<script>" not in html
    assert "<script>" not in md
    assert "[click](https://evil.test)" not in md

def test_cli_local_end_to_end(lab, identities, tmp_path):
    config = json.loads((ROOT / "input/lab_config.json").read_text())
    for name, headers in identities.items():
        path = tmp_path / (name+".token")
        path.write_text(headers["Authorization"][7:])
        config["identities"][name]["token_file"] = path.name
    configpath = tmp_path / "config.json"
    configpath.write_text(json.dumps(config))
    output = tmp_path / "output"
    args = parser().parse_args(["--target", lab[1], "--openapi", str(ROOT / "input/openapi.json"), "--config", str(configpath), "--bola", "--rate-limit-path", "/api/limited", "--rate-limit-delay", "0.2", "--output", str(output)])
    paths = run(args)
    assert len(paths) == 3
    report = json.loads((output/"evidence.json").read_text())
    assert report["severity_summary"]["High"] == 1
    assert report["severity_summary"]["Medium"] == 2
    assert report["coverage"]["requests_sent"] <= 100
    assert any(f["title"] == "Rate limiting observed" for f in report["findings"])
    for path in paths:
        value = path.read_text()
        for headers in identities.values():
            assert headers["Authorization"][7:] not in value
        assert "Synthetic Alice notebook" not in value

def test_cli_bad_configuration_and_environment(tmp_path):
    assert main(["--target", "https://example.com", "--output", str(tmp_path)]) == 2
    assert main(["--check-environment"]) == 0
