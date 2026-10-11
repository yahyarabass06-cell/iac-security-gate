"""Evaluate captured Terraform reports through the security policy."""

from pathlib import Path

from iac_security_gate.policy import evaluate_policy
from iac_security_gate.trivy_reader import load_trivy_report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "trivy"


def test_unrestricted_ssh_blocks_default_policy():
    findings = load_trivy_report(FIXTURES / "unsafe.json")
    decision = evaluate_policy(findings)

    assert not decision.passed
    assert len(decision.blocked) == 1
    assert decision.blocked[0].check_id == "AWS-0107"
    assert decision.blocked[0].severity == "HIGH"
    assert decision.allowed == ()


def test_restricted_fixture_passes_default_policy():
    findings = load_trivy_report(FIXTURES / "restricted.json")
    decision = evaluate_policy(findings)

    assert decision.passed
    assert decision.blocked == decision.allowed == ()
