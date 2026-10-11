"""Read the supported Trivy Terraform report format."""

import json
from pathlib import Path

from iac_security_gate.models import Finding


class ReportError(ValueError):
    """The report is invalid or outside the supported scope."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ReportError("Non-standard JSON constant")


def _count(summary, name):
    value = summary.get(name)
    if type(value) is not int or value < 0:
        raise ReportError(f"Invalid summary count: {name}")
    return value


def parse_trivy_report(report: object) -> tuple[Finding, ...]:
    """Validate schema 2 Terraform results with failure-only findings."""
    if not isinstance(report, dict):
        raise ReportError("Report must be an object")
    if type(report.get("SchemaVersion")) is not int:
        raise ReportError("Invalid schema version")
    if report["SchemaVersion"] != 2:
        raise ReportError("Unsupported schema version")

    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ReportError("Expected non-empty scan results")

    findings = []
    checks = 0

    for result in results:
        if not isinstance(result, dict):
            raise ReportError("Result must be an object")
        if result.get("Class") != "config" or result.get("Type") != "terraform":
            raise ReportError("Only Terraform configuration results are supported")

        target = result.get("Target")
        if not isinstance(target, str) or not target.strip():
            raise ReportError("Missing result target")

        summary = result.get("MisconfSummary")
        if not isinstance(summary, dict):
            raise ReportError("Missing scan summary")

        successes = _count(summary, "Successes")
        failures = _count(summary, "Failures")
        exceptions = summary.get("Exceptions", 0)
        if type(exceptions) is not int or exceptions != 0:
            raise ReportError("Scanner-side exceptions are not supported")
        checks += successes + failures

        entries = result.get("Misconfigurations", [])
        if not isinstance(entries, list):
            raise ReportError("Misconfigurations must be a list")
        if len(entries) != failures:
            raise ReportError("Failure count does not match reported findings")

        for entry in entries:
            if not isinstance(entry, dict) or entry.get("Status") != "FAIL":
                raise ReportError("Expected a failed check")

            metadata = entry.get("CauseMetadata", {})
            if not isinstance(metadata, dict):
                raise ReportError("Invalid cause metadata")

            try:
                finding = Finding(
                    check_id=entry.get("ID"),
                    target=target,
                    severity=entry.get("Severity"),
                    title=entry.get("Title"),
                    description=entry.get("Description"),
                    resource=metadata.get("Resource"),
                    start_line=metadata.get("StartLine"),
                    end_line=metadata.get("EndLine"),
                )
            except ValueError:
                raise ReportError("Invalid finding fields") from None

            findings.append(finding)

    if checks == 0:
        raise ReportError("No executed checks recorded")

    return tuple(findings)


def load_trivy_report(path: Path) -> tuple[Finding, ...]:
    """Load a UTF-8 JSON report without exposing its contents in errors."""
    try:
        report = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, ValueError):
        raise ReportError("Report could not be loaded") from None

    return parse_trivy_report(report)
