"""Apply exceptions while retaining evidence and exception audit details."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from iac_security_gate.comparison import compare_findings
from iac_security_gate.exceptions import SecurityException
from iac_security_gate.models import Finding


@dataclass(frozen=True)
class AppliedException:
    finding: Finding
    exception: SecurityException


@dataclass(frozen=True)
class ExceptionEvaluation:
    remaining: tuple[Finding, ...]
    applied: tuple[AppliedException, ...]
    expired: tuple[SecurityException, ...]
    unmatched: tuple[SecurityException, ...]


def apply_exceptions(
    findings: Iterable[Finding],
    exceptions: Iterable[SecurityException],
    *,
    today: date,
) -> ExceptionEvaluation:
    """Apply exact, active exceptions; reject ambiguous scopes."""
    if type(today) is not date:
        raise ValueError("Evaluation date must be a date")

    ordered_findings = compare_findings((), findings).added
    indexed = {}

    for exception in exceptions:
        if not isinstance(exception, SecurityException):
            raise ValueError("Expected validated exceptions")
        if exception.identity in indexed:
            raise ValueError("Ambiguous duplicate exception scope")
        indexed[exception.identity] = exception

    remaining = []
    applied = []
    used = set()

    for finding in ordered_findings:
        exception = indexed.get(finding.identity)
        if (
            exception is not None
            and exception.is_active_on(today)
            and exception.matches(finding)
        ):
            applied.append(AppliedException(finding, exception))
            used.add(exception.identity)
        else:
            remaining.append(finding)

    ordered_exceptions = [indexed[key] for key in sorted(indexed)]

    return ExceptionEvaluation(
        remaining=tuple(remaining),
        applied=tuple(applied),
        expired=tuple(
            item for item in ordered_exceptions if not item.is_active_on(today)
        ),
        unmatched=tuple(
            item
            for item in ordered_exceptions
            if item.is_active_on(today) and item.identity not in used
        ),
    )
