"""Verify configurable blocking decisions and conservative defaults."""

from dataclasses import replace

import pytest

from iac_security_gate.models import Finding
from iac_security_gate.policy import Policy, evaluate_policy


@pytest.fixture
def finding():
    return Finding(
        check_id="AWS-0107",
        target="main.tf",
        severity="HIGH",
        title="Unrestricted SSH ingress",
        description="Synthetic finding.",
        resource="aws_security_group.lab_ssh",
    )


@pytest.mark.parametrize(
    ("severity", "should_pass"),
    [
        ("LOW", True),
        ("MEDIUM", True),
        ("HIGH", False),
        ("CRITICAL", False),
        ("UNKNOWN", False),
    ],
)
def test_default_policy(finding, severity, should_pass):
    current = replace(finding, severity=severity)
    decision = evaluate_policy([current])

    assert decision.passed is should_pass
    assert decision.blocked == (() if should_pass else (current,))
    assert decision.allowed == ((current,) if should_pass else ())


def test_empty_findings_pass_policy():
    decision = evaluate_policy([])
    assert decision.passed
    assert decision.blocked == decision.allowed == ()


def test_custom_policy_can_block_medium(finding):
    current = replace(finding, severity="MEDIUM")
    policy = Policy(
        blocked_severities=frozenset({"MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})
    )
    assert not evaluate_policy([current], policy).passed


def test_mixed_findings_preserve_decision_evidence(finding):
    low = replace(finding, check_id="LAB-0001", severity="LOW")
    decision = evaluate_policy([low, finding])
    assert decision.blocked == (finding,)
    assert decision.allowed == (low,)
    assert not decision.passed


@pytest.mark.parametrize(
    "severities",
    [
        frozenset(),
        frozenset({"URGENT"}),
        {"HIGH"},
        "HIGH",
    ],
)
def test_invalid_policy_is_rejected(severities):
    with pytest.raises(ValueError):
        Policy(blocked_severities=severities)


def test_duplicate_findings_cannot_be_silently_accepted(finding):
    with pytest.raises(ValueError, match="Ambiguous"):
        evaluate_policy([finding, finding])


def test_invalid_policy_object_is_rejected(finding):
    with pytest.raises(ValueError, match="validated policy"):
        evaluate_policy([finding], None)
