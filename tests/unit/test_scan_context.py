"""Test report provenance and observable compatibility checks."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from iac_security_gate.scan_context import (
    check_compatibility,
    load_scan_report,
)
from iac_security_gate.trivy_reader import ReportError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "trivy"


def test_provenance_matches_input_bytes():
    path = FIXTURES / "unsafe.json"
    scan = load_scan_report(path)

    assert scan.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert scan.scanner_version == "0.75.0"
    assert scan.artifact_name == "examples/terraform/unsafe"
    assert len(scan.findings) == 1


def test_same_report_keeps_unverified_context_warning():
    scan = load_scan_report(FIXTURES / "unsafe.json")
    warnings = check_compatibility(scan, scan)
    assert len(warnings) == 1
    assert "not verified" in warnings[0]


def test_different_roots_require_explicit_allowance():
    baseline = load_scan_report(FIXTURES / "restricted.json")
    current = load_scan_report(FIXTURES / "unsafe.json")
    with pytest.raises(ReportError, match="roots differ"):
        check_compatibility(baseline, current)


def test_explicit_root_change_retains_warning():
    baseline = load_scan_report(FIXTURES / "restricted.json")
    current = load_scan_report(FIXTURES / "unsafe.json")
    warnings = check_compatibility(baseline, current, allow_root_change=True)
    assert len(warnings) == 2
    assert "accepted explicitly" in warnings[1]


def test_root_allowance_does_not_bypass_version_check():
    scan = load_scan_report(FIXTURES / "unsafe.json")
    changed = replace(scan, scanner_version="different-version")
    with pytest.raises(ReportError, match="versions differ"):
        check_compatibility(scan, changed, allow_root_change=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Trivy", None),
        ("Trivy", {}),
        ("Trivy", {"Version": ""}),
        ("Trivy", {"Version": 75}),
        ("ArtifactName", None),
        ("ArtifactName", ""),
        ("ArtifactType", "container_image"),
    ],
)
def test_invalid_metadata_is_rejected(tmp_path, field, value):
    report = json.loads((FIXTURES / "unsafe.json").read_text(encoding="utf-8"))
    report[field] = value
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ReportError):
        load_scan_report(path)
