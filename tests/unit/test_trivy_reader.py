"""Validate captured reports and reject incomplete scan evidence."""

import json
from pathlib import Path

import pytest

from iac_security_gate.trivy_reader import (
    ReportError,
    load_trivy_report,
    parse_trivy_report,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "trivy"


def test_unsafe_fixture_has_traceable_finding():
    findings = load_trivy_report(FIXTURES / "unsafe.json")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.identity == ("AWS-0107", "main.tf", "aws_security_group.lab_ssh")
    assert finding.severity == "HIGH"
    assert finding.start_line == finding.end_line == 13


def test_restricted_fixture_has_no_findings():
    assert load_trivy_report(FIXTURES / "restricted.json") == ()


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        {},
        {"SchemaVersion": True, "Results": []},
        {"SchemaVersion": 3, "Results": []},
        {"SchemaVersion": 2, "Results": []},
        {"SchemaVersion": 2, "Results": [None]},
    ],
)
def test_invalid_report_structure(report):
    with pytest.raises(ReportError):
        parse_trivy_report(report)


@pytest.mark.parametrize(
    ("successes", "failures", "exceptions"),
    [
        (0, 0, 0),
        (71, 1, 0),
        (True, 0, 0),
        (-1, 0, 0),
        (71, 0, 1),
    ],
)
def test_invalid_or_inconsistent_summary(successes, failures, exceptions):
    report = json.loads((FIXTURES / "restricted.json").read_text())
    report["Results"][0]["MisconfSummary"] = {
        "Successes": successes,
        "Failures": failures,
        "Exceptions": exceptions,
    }
    with pytest.raises(ReportError):
        parse_trivy_report(report)


@pytest.mark.parametrize(
    "content",
    [
        "{",
        '{"SchemaVersion": 2, "SchemaVersion": 2}',
        '{"SchemaVersion": NaN}',
    ],
)
def test_invalid_json_is_rejected(tmp_path, content):
    path = tmp_path / "report.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ReportError):
        load_trivy_report(path)


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(ReportError):
        load_trivy_report(tmp_path / "missing.json")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ID", None),
        ("ID", ""),
        ("Severity", "URGENT"),
        ("Severity", None),
        ("Title", ""),
        ("Description", None),
        ("Status", "PASS"),
        ("Status", None),
        ("CauseMetadata", []),
        ("CauseMetadata", {"Resource": ""}),
        ("CauseMetadata", {"StartLine": 13}),
        ("CauseMetadata", {"StartLine": True, "EndLine": 13}),
        ("CauseMetadata", {"StartLine": 14, "EndLine": 13}),
    ],
)
def test_invalid_finding_fields(field, value):
    report = json.loads((FIXTURES / "unsafe.json").read_text(encoding="utf-8"))
    report["Results"][1]["Misconfigurations"][0][field] = value
    with pytest.raises(ReportError):
        parse_trivy_report(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Class", "os-pkgs"),
        ("Type", "dockerfile"),
        ("Target", None),
        ("Target", "."),
        ("Target", "../main.tf"),
        ("MisconfSummary", None),
        ("Misconfigurations", None),
        ("Misconfigurations", {}),
    ],
)
def test_invalid_finding_result(field, value):
    report = json.loads((FIXTURES / "unsafe.json").read_text(encoding="utf-8"))
    report["Results"][1][field] = value
    with pytest.raises(ReportError):
        parse_trivy_report(report)


def test_absent_optional_evidence_is_not_invented():
    report = json.loads((FIXTURES / "unsafe.json").read_text(encoding="utf-8"))
    entry = report["Results"][1]["Misconfigurations"][0]
    entry.pop("CauseMetadata")

    finding = parse_trivy_report(report)[0]

    assert finding.resource is None
    assert finding.start_line is None
    assert finding.end_line is None


def test_missing_scan_summary_is_rejected():
    report = json.loads((FIXTURES / "restricted.json").read_text(encoding="utf-8"))
    report["Results"][0].pop("MisconfSummary")
    with pytest.raises(ReportError):
        parse_trivy_report(report)
