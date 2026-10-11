"""Deterministic comparison of findings from comparable scan contexts."""

from collections.abc import Iterable
from dataclasses import dataclass

from iac_security_gate.models import Finding

Identity = tuple[str, str, str | None]


@dataclass(frozen=True)
class SeverityChange:
    """Previous and current evidence for a severity change."""

    previous: Finding
    current: Finding


@dataclass(frozen=True)
class Comparison:
    """Mutually exclusive finding categories."""

    added: tuple[Finding, ...]
    removed: tuple[Finding, ...]
    unchanged: tuple[Finding, ...]
    severity_changed: tuple[SeverityChange, ...]


def _index(findings: Iterable[Finding]) -> dict[Identity, Finding]:
    indexed = {}
    for finding in findings:
        if not isinstance(finding, Finding):
            raise ValueError("Comparison expects validated findings")
        if finding.identity in indexed:
            raise ValueError("Ambiguous duplicate finding identity")
        indexed[finding.identity] = finding
    return indexed


def _sort_key(identity: Identity) -> tuple[str, str, str]:
    check_id, target, resource = identity
    return check_id, target, resource or ""


def compare_findings(
    baseline: Iterable[Finding],
    current: Iterable[Finding],
) -> Comparison:
    """Compare findings; callers must establish scan-context compatibility."""
    previous = _index(baseline)
    latest = _index(current)

    previous_ids = set(previous)
    latest_ids = set(latest)

    added = tuple(
        latest[key] for key in sorted(latest_ids - previous_ids, key=_sort_key)
    )
    removed = tuple(
        previous[key] for key in sorted(previous_ids - latest_ids, key=_sort_key)
    )

    unchanged = []
    changes = []

    for key in sorted(previous_ids & latest_ids, key=_sort_key):
        before = previous[key]
        after = latest[key]
        if before.severity == after.severity:
            unchanged.append(after)
        else:
            changes.append(SeverityChange(previous=before, current=after))

    return Comparison(
        added=added,
        removed=removed,
        unchanged=tuple(unchanged),
        severity_changed=tuple(changes),
    )
