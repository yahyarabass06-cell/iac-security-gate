"""Test security regressions, evidence changes and ambiguous identities."""

from dataclasses import replace

import pytest

from iac_security_gate.comparison import compare_findings
from iac_security_gate.models import Finding


@pytest.fixture
def finding():
    return Finding(
        check_id="AWS-0107",
        target="main.tf",
        severity="HIGH",
        title="Unrestricted SSH ingress",
        description="Synthetic finding.",
        resource="aws_security_group.lab_ssh",
        start_line=13,
        end_line=13,
    )


def test_empty_scans():
    result = compare_findings([], [])
    assert result.added == result.removed == result.unchanged == ()
    assert result.severity_changed == ()


def test_new_finding(finding):
    result = compare_findings([], [finding])
    assert result.added == (finding,)
    assert result.removed == result.unchanged == ()
    assert result.severity_changed == ()


def test_absent_finding(finding):
    result = compare_findings([finding], [])
    assert result.removed == (finding,)
    assert result.added == result.unchanged == ()
    assert result.severity_changed == ()


def test_line_change_preserves_identity(finding):
    moved = replace(finding, start_line=20, end_line=20)
    result = compare_findings([finding], [moved])
    assert result.unchanged == (moved,)
    assert result.added == result.removed == ()
    assert result.severity_changed == ()


@pytest.mark.parametrize("severity", ["LOW", "CRITICAL", "UNKNOWN"])
def test_severity_change_preserves_both_versions(finding, severity):
    changed = replace(finding, severity=severity)
    result = compare_findings([finding], [changed])
    assert result.added == result.removed == result.unchanged == ()
    assert len(result.severity_changed) == 1
    assert result.severity_changed[0].previous == finding
    assert result.severity_changed[0].current == changed


def test_resource_change_is_removal_and_addition(finding):
    changed = replace(finding, resource="aws_security_group.other")
    result = compare_findings([finding], [changed])
    assert result.removed == (finding,)
    assert result.added == (changed,)
    assert result.unchanged == result.severity_changed == ()


def test_input_order_does_not_change_output(finding):
    other = replace(finding, check_id="AWS-0001", resource=None)
    first = compare_findings([], [finding, other])
    second = compare_findings([], [other, finding])
    assert first == second
    assert first.added == (other, finding)


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_duplicate_identity_is_rejected(finding, side):
    duplicate = replace(finding, start_line=30, end_line=30)
    arguments = {"baseline": [], "current": []}
    arguments[side] = [finding, duplicate]
    with pytest.raises(ValueError, match="Ambiguous"):
        compare_findings(**arguments)


def test_unvalidated_input_is_rejected():
    with pytest.raises(ValueError, match="validated"):
        compare_findings([], [None])
