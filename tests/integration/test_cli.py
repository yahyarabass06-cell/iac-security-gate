"""Validate CLI reports, exit codes and failure behavior."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "trivy"


def run_cli(baseline="restricted", current="unsafe", extra=()):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "iac_security_gate.cli",
            "--baseline",
            str(FIXTURES / f"{baseline}.json"),
            "--current",
            str(FIXTURES / f"{current}.json"),
            "--policy",
            str(ROOT / "config" / "policy.json"),
            "--exceptions",
            str(ROOT / "config" / "exceptions.json"),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_blocking_policy_returns_one_and_json():
    result = run_cli(extra=("--allow-root-change",))
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["gate"] == "block"
    assert report["summary"]["blocked"] == 1
    assert result.stderr == ""


def test_passing_policy_returns_zero():
    result = run_cli("unsafe", "restricted", ("--allow-root-change",))
    assert result.returncode == 0
    assert json.loads(result.stdout)["gate"] == "pass"


def test_incompatible_roots_return_error_without_report():
    result = run_cli()
    assert result.returncode == 2
    assert result.stdout == ""
    assert "Analysis failed" in result.stderr


def test_missing_input_returns_error():
    result = run_cli(current="missing", extra=("--allow-root-change",))
    assert result.returncode == 2
    assert result.stdout == ""


def test_replay_date_is_visible():
    result = run_cli(extra=("--allow-root-change", "--evaluation-date", "2026-10-11"))
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["evaluation_date"] == "2026-10-11"
    assert report["configuration"]["evaluation_date_source"] == "explicit_replay"


def test_invalid_date_is_usage_error():
    result = run_cli(extra=("--evaluation-date", "20261011"))
    assert result.returncode == 2
    assert result.stdout == ""
    assert "YYYY-MM-DD" in result.stderr


def test_blocked_report_can_be_exported(tmp_path):
    path = tmp_path / "assessment.json"
    result = run_cli(extra=("--allow-root-change", "--output", str(path)))
    assert result.returncode == 1
    assert result.stdout == ""
    assert json.loads(path.read_text())["gate"] == "block"


def test_export_collision_returns_analysis_error(tmp_path):
    path = tmp_path / "assessment.json"
    path.write_text("original")
    result = run_cli(extra=("--allow-root-change", "--output", str(path)))
    assert result.returncode == 2
    assert result.stdout == ""
    assert path.read_text() == "original"


def test_missing_output_directory_returns_error(tmp_path):
    path = tmp_path / "missing" / "assessment.json"
    result = run_cli(extra=("--allow-root-change", "--output", str(path)))
    assert result.returncode == 2
    assert not path.exists()
