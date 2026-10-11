"""Check complete assessments using captured scan evidence."""

import json
from datetime import date
from pathlib import Path

import pytest

from iac_security_gate.exceptions import SecurityException
from iac_security_gate.policy import Policy
from iac_security_gate.reporting import build_assessment
from iac_security_gate.scan_context import load_scan_report
from iac_security_gate.trivy_reader import ReportError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "trivy"


def assess(baseline_name, current_name, exceptions=(), day=11):
    return build_assessment(
        load_scan_report(FIXTURES / f"{baseline_name}.json"),
        load_scan_report(FIXTURES / f"{current_name}.json"),
        policy=Policy(),
        exceptions=exceptions,
        evaluation_date=date(2026, 10, day),
        allow_root_change=True,
    )


def test_new_high_finding_blocks_and_is_traceable():
    report = assess("restricted", "unsafe")
    assert report["gate"] == "block"
    assert report["summary"]["added"] == 1
    assert report["summary"]["blocked"] == 1
    finding = report["decision"]["blocked"][0]
    assert finding["check_id"] == "AWS-0107"
    assert finding["start_line"] == 13
    assert len(report["inputs"]["current"]["sha256"]) == 64
    assert report["warnings"]
    assert json.loads(json.dumps(report)) == report


def test_existing_high_finding_still_blocks():
    report = assess("unsafe", "unsafe")
    assert report["summary"]["added"] == 0
    assert report["summary"]["unchanged"] == 1
    assert report["gate"] == "block"


def test_absent_finding_is_reported_without_blocking():
    report = assess("unsafe", "restricted")
    assert report["summary"]["removed"] == 1
    assert report["gate"] == "pass"


@pytest.mark.parametrize(
    ("day", "expected_gate", "excepted", "expired"),
    [(11, "pass", 1, 0), (12, "block", 0, 1)],
)
def test_exception_is_visible_and_expires(day, expected_gate, excepted, expired):
    exception = SecurityException(
        check_id="AWS-0107",
        target="main.tf",
        resource="aws_security_group.lab_ssh",
        severity="HIGH",
        justification="Synthetic acceptance for assessment tests.",
        expires_on=date(2026, 10, 12),
    )
    report = assess("restricted", "unsafe", (exception,), day)
    assert report["gate"] == expected_gate
    assert report["summary"]["excepted"] == excepted
    assert report["summary"]["expired_exceptions"] == expired
    assert report["summary"]["current_findings"] == 1
    assert json.loads(json.dumps(report)) == report


def test_incompatible_roots_do_not_produce_success_report():
    with pytest.raises(ReportError, match="roots differ"):
        build_assessment(
            load_scan_report(FIXTURES / "restricted.json"),
            load_scan_report(FIXTURES / "unsafe.json"),
            policy=Policy(),
            exceptions=(),
            evaluation_date=date(2026, 10, 11),
        )
