"""Capture report provenance and check observable scan compatibility."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from iac_security_gate.models import Finding
from iac_security_gate.trivy_reader import (
    ReportError,
    parse_trivy_report,
)


@dataclass(frozen=True)
class ScanReport:
    source_file: str
    sha256: str
    scanner_version: str
    artifact_name: str
    findings: tuple[Finding, ...]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ReportError("Non-standard JSON constant")


def load_scan_report(path: Path) -> ScanReport:
    """Hash and parse the same input bytes, retaining scanner metadata."""
    try:
        raw = path.read_bytes()
        report = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, ValueError):
        raise ReportError("Scan report could not be loaded") from None

    findings = parse_trivy_report(report)

    if report.get("ArtifactType") != "filesystem":
        raise ReportError("Only filesystem scan reports are supported")

    artifact = report.get("ArtifactName")
    scanner = report.get("Trivy")
    if not isinstance(scanner, dict):
        raise ReportError("Missing scanner metadata")
    version = scanner.get("Version")

    for value in (artifact, version):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise ReportError("Invalid scan context metadata")

    return ScanReport(
        source_file=str(path),
        sha256=hashlib.sha256(raw).hexdigest(),
        scanner_version=version,
        artifact_name=artifact,
        findings=findings,
    )


def check_compatibility(
    baseline: ScanReport,
    current: ScanReport,
    *,
    allow_root_change: bool = False,
) -> tuple[str, ...]:
    """Check observable compatibility and return remaining limitations."""
    if not isinstance(baseline, ScanReport) or not isinstance(current, ScanReport):
        raise ReportError("Expected validated scan reports")
    if type(allow_root_change) is not bool:
        raise ReportError("allow_root_change must be a boolean")

    if baseline.scanner_version != current.scanner_version:
        raise ReportError("Scanner versions differ")

    warnings = ["Rule bundle versions and scan options are not verified by this check."]

    if baseline.artifact_name != current.artifact_name:
        if not allow_root_change:
            raise ReportError("Scan roots differ; explicit allowance is required")
        warnings.append(
            "Different scan roots accepted explicitly; equivalent scope "
            "and relative resource paths must be established by the caller."
        )

    return tuple(warnings)
