"""Verify temporary exceptions against a captured Trivy finding."""

from datetime import date
from pathlib import Path

import pytest

from iac_security_gate.exception_evaluation import apply_exceptions
from iac_security_gate.exceptions import SecurityException
from iac_security_gate.policy import evaluate_policy
from iac_security_gate.trivy_reader import load_trivy_report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "trivy"


@pytest.mark.parametrize(
    ("evaluation_date", "should_pass"),
    [
        (date(2026, 10, 11), True),
        (date(2026, 10, 12), False),
    ],
)
def test_exception_expiration_controls_gate(evaluation_date, should_pass):
    findings = load_trivy_report(FIXTURES / "unsafe.json")
    exception = SecurityException(
        check_id="AWS-0107",
        target="main.tf",
        resource="aws_security_group.lab_ssh",
        severity="HIGH",
        justification="Synthetic acceptance to test expiration behavior.",
        expires_on=date(2026, 10, 12),
    )

    result = apply_exceptions(findings, [exception], today=evaluation_date)
    decision = evaluate_policy(result.remaining)

    assert decision.passed is should_pass

    if should_pass:
        assert len(result.applied) == 1
        assert result.applied[0].finding == findings[0]
        assert result.applied[0].exception.justification == exception.justification
        assert result.expired == ()
    else:
        assert result.applied == ()
        assert result.expired == (exception,)
        assert decision.blocked == findings
