"""Compare captured Trivy reports through the validated reader."""

from pathlib import Path

from iac_security_gate.comparison import compare_findings
from iac_security_gate.trivy_reader import load_trivy_report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "trivy"


def test_restricted_to_unsafe_detects_regression():
    baseline = load_trivy_report(FIXTURES / "restricted.json")
    current = load_trivy_report(FIXTURES / "unsafe.json")

    result = compare_findings(baseline, current)

    assert len(result.added) == 1
    assert result.added[0].identity == (
        "AWS-0107",
        "main.tf",
        "aws_security_group.lab_ssh",
    )
    assert result.added[0].severity == "HIGH"
    assert result.removed == result.unchanged == ()
    assert result.severity_changed == ()


def test_unsafe_to_restricted_reports_absence():
    baseline = load_trivy_report(FIXTURES / "unsafe.json")
    current = load_trivy_report(FIXTURES / "restricted.json")

    result = compare_findings(baseline, current)

    assert len(result.removed) == 1
    assert result.removed[0].check_id == "AWS-0107"
    assert result.added == result.unchanged == ()
    assert result.severity_changed == ()


def test_same_report_has_no_regression():
    findings = load_trivy_report(FIXTURES / "unsafe.json")

    result = compare_findings(findings, findings)

    assert result.unchanged == findings
    assert result.added == result.removed == ()
    assert result.severity_changed == ()
