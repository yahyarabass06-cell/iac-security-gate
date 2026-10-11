"""Tests for finding validation and stable identity."""

from dataclasses import FrozenInstanceError, replace

import pytest

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


def test_identity_ignores_severity_and_line_changes(finding):
    changed = replace(finding, severity="CRITICAL", start_line=20, end_line=22)
    assert changed.identity == finding.identity


def test_resource_change_changes_identity(finding):
    changed = replace(finding, resource="aws_security_group.other")
    assert changed.identity != finding.identity


def test_optional_evidence_can_be_absent(finding):
    changed = replace(finding, resource=None, start_line=None, end_line=None)
    assert changed.identity == ("AWS-0107", "main.tf", None)


def test_finding_is_immutable(finding):
    with pytest.raises(FrozenInstanceError):
        finding.severity = "LOW"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("check_id", ""),
        ("check_id", " AWS-0107"),
        ("title", None),
        ("severity", "URGENT"),
        ("description", None),
        ("resource", ""),
        ("resource", 123),
        ("target", "/tmp/main.tf"),
        ("target", "../main.tf"),
        ("target", "dir/../main.tf"),
        ("target", "dir//main.tf"),
        ("target", "./main.tf"),
        ("target", "dir\\main.tf"),
        ("target", "C:/main.tf"),
        ("target", "."),
        ("start_line", 0),
        ("start_line", True),
        ("start_line", 1.5),
        ("start_line", None),
        ("end_line", None),
        ("end_line", 12),
    ],
)
def test_invalid_fields_are_rejected(finding, field, value):
    with pytest.raises(ValueError):
        replace(finding, **{field: value})
