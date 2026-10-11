"""Build an explainable security gate assessment."""

from dataclasses import asdict
from datetime import date

from iac_security_gate.comparison import compare_findings
from iac_security_gate.exception_evaluation import apply_exceptions
from iac_security_gate.exceptions import SecurityException
from iac_security_gate.policy import Policy, evaluate_policy
from iac_security_gate.scan_context import ScanReport, check_compatibility


def _exception_dict(exception: SecurityException) -> dict:
    result = asdict(exception)
    result["expires_on"] = exception.expires_on.isoformat()
    return result


def _provenance(scan: ScanReport) -> dict:
    return {
        "source_file": scan.source_file,
        "sha256": scan.sha256,
        "scanner_version": scan.scanner_version,
        "artifact_name": scan.artifact_name,
    }


def build_assessment(
    baseline: ScanReport,
    current: ScanReport,
    *,
    policy: Policy,
    exceptions: tuple[SecurityException, ...],
    evaluation_date: date,
    allow_root_change: bool = False,
) -> dict:
    """Evaluate all current findings and preserve comparison evidence."""
    warnings = check_compatibility(
        baseline, current, allow_root_change=allow_root_change
    )
    comparison = compare_findings(baseline.findings, current.findings)
    exception_result = apply_exceptions(
        current.findings, exceptions, today=evaluation_date
    )
    decision = evaluate_policy(exception_result.remaining, policy)

    return {
        "schema_version": 1,
        "analysis_status": "complete",
        "gate": "pass" if decision.passed else "block",
        "evaluation_date": evaluation_date.isoformat(),
        "inputs": {
            "baseline": _provenance(baseline),
            "current": _provenance(current),
        },
        "configuration": {
            "blocked_severities": sorted(policy.blocked_severities),
            "allow_root_change": allow_root_change,
            "exceptions": [_exception_dict(item) for item in exceptions],
        },
        "warnings": list(warnings),
        "summary": {
            "current_findings": len(current.findings),
            "added": len(comparison.added),
            "removed": len(comparison.removed),
            "unchanged": len(comparison.unchanged),
            "severity_changed": len(comparison.severity_changed),
            "blocked": len(decision.blocked),
            "allowed": len(decision.allowed),
            "excepted": len(exception_result.applied),
            "expired_exceptions": len(exception_result.expired),
            "unmatched_exceptions": len(exception_result.unmatched),
        },
        "comparison": {
            "added": [asdict(item) for item in comparison.added],
            "removed": [asdict(item) for item in comparison.removed],
            "unchanged": [asdict(item) for item in comparison.unchanged],
            "severity_changed": [
                {
                    "previous": asdict(item.previous),
                    "current": asdict(item.current),
                }
                for item in comparison.severity_changed
            ],
        },
        "decision": {
            "blocked": [asdict(item) for item in decision.blocked],
            "allowed": [asdict(item) for item in decision.allowed],
            "excepted": [
                {
                    "finding": asdict(item.finding),
                    "exception": _exception_dict(item.exception),
                }
                for item in exception_result.applied
            ],
            "expired_exceptions": [
                _exception_dict(item) for item in exception_result.expired
            ],
            "unmatched_exceptions": [
                _exception_dict(item) for item in exception_result.unmatched
            ],
        },
    }
