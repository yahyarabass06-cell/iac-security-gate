"""Verify exception scope, expiration boundaries and severity binding."""

from dataclasses import replace
from datetime import date, datetime

import pytest

from iac_security_gate.exceptions import SecurityException
from iac_security_gate.models import Finding


@pytest.fixture
def exception():
    return SecurityException(
        check_id="AWS-0107",
        target="main.tf",
        resource="aws_security_group.lab_ssh",
        severity="HIGH",
        justification="Synthetic lab exception for testing.",
        expires_on=date(2026, 10, 12),
    )


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


def test_exception_active_before_expiration(exception):
    assert exception.is_active_on(date(2026, 10, 11))


@pytest.mark.parametrize("day", [12, 13])
def test_exception_inactive_on_or_after_expiration(exception, day):
    assert not exception.is_active_on(date(2026, 10, day))


def test_exact_scope_matches(exception, finding):
    assert exception.matches(finding)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("check_id", "AWS-9999"),
        ("target", "other.tf"),
        ("resource", "aws_security_group.other"),
        ("resource", None),
        ("severity", "CRITICAL"),
    ],
)
def test_different_scope_or_severity_does_not_match(exception, finding, field, value):
    assert not exception.matches(replace(finding, **{field: value}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("resource", None),
        ("resource", ""),
        ("target", "../main.tf"),
        ("severity", "URGENT"),
        ("justification", ""),
        ("justification", "   "),
        ("justification", None),
        ("expires_on", "2026-10-12"),
        ("expires_on", datetime(2026, 10, 12)),
    ],
)
def test_invalid_exception_is_rejected(exception, field, value):
    with pytest.raises(ValueError):
        replace(exception, **{field: value})


def test_invalid_evaluation_date_is_rejected(exception):
    with pytest.raises(ValueError):
        exception.is_active_on("2026-10-11")
