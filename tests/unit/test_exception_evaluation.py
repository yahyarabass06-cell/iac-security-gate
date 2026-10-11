"""Test exception application and retained audit evidence."""

from dataclasses import replace
from datetime import date

import pytest

from iac_security_gate.exception_evaluation import apply_exceptions
from iac_security_gate.exceptions import SecurityException
from iac_security_gate.models import Finding
from iac_security_gate.policy import evaluate_policy

TODAY = date(2026, 10, 11)


@pytest.fixture
def finding():
    return Finding(
        check_id="AWS-0107",
        target="main.tf",
        resource="aws_security_group.lab_ssh",
        severity="HIGH",
        title="Unrestricted SSH ingress",
        description="Synthetic finding.",
    )


@pytest.fixture
def exception():
    return SecurityException(
        check_id="AWS-0107",
        target="main.tf",
        resource="aws_security_group.lab_ssh",
        severity="HIGH",
        justification="Temporary synthetic lab acceptance.",
        expires_on=date(2026, 10, 12),
    )


def test_active_exception_retains_evidence(finding, exception):
    result = apply_exceptions([finding], [exception], today=TODAY)
    assert result.remaining == ()
    assert len(result.applied) == 1
    assert result.applied[0].finding == finding
    assert result.applied[0].exception == exception
    assert result.expired == result.unmatched == ()
    assert evaluate_policy(result.remaining).passed


def test_expired_exception_does_not_bypass_policy(finding, exception):
    result = apply_exceptions([finding], [exception], today=exception.expires_on)
    assert result.remaining == (finding,)
    assert result.expired == (exception,)
    assert result.applied == result.unmatched == ()
    assert not evaluate_policy(result.remaining).passed


def test_severity_escalation_remains_blocking(finding, exception):
    escalated = replace(finding, severity="CRITICAL")
    result = apply_exceptions([escalated], [exception], today=TODAY)
    assert result.remaining == (escalated,)
    assert result.unmatched == (exception,)
    assert result.applied == ()
    assert not evaluate_policy(result.remaining).passed


def test_unmatched_exception_is_reported(exception):
    result = apply_exceptions([], [exception], today=TODAY)
    assert result.unmatched == (exception,)
    assert result.applied == result.remaining == ()


def test_no_exception_keeps_finding(finding):
    result = apply_exceptions([finding], [], today=TODAY)
    assert result.remaining == (finding,)
    assert result.applied == result.expired == result.unmatched == ()


def test_duplicate_scope_is_rejected(exception):
    other = replace(exception, expires_on=date(2026, 10, 20))
    with pytest.raises(ValueError, match="Ambiguous"):
        apply_exceptions([], [exception, other], today=TODAY)


def test_unvalidated_exception_is_rejected():
    with pytest.raises(ValueError, match="validated"):
        apply_exceptions([], [None], today=TODAY)


def test_invalid_evaluation_date_is_rejected():
    with pytest.raises(ValueError, match="date"):
        apply_exceptions([], [], today="2026-10-11")
