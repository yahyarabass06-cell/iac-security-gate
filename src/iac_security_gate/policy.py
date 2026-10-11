"""Explicit severity-based security gate decisions."""

from collections.abc import Iterable
from dataclasses import dataclass

from iac_security_gate.comparison import compare_findings
from iac_security_gate.models import SEVERITIES, Finding


@dataclass(frozen=True)
class Policy:
    """Severities requiring a blocking decision."""

    blocked_severities: frozenset[str] = frozenset({"HIGH", "CRITICAL", "UNKNOWN"})

    def __post_init__(self) -> None:
        if not isinstance(self.blocked_severities, frozenset):
            raise ValueError("blocked_severities must be a frozenset")
        if not self.blocked_severities:
            raise ValueError("At least one blocking severity is required")
        if not self.blocked_severities <= SEVERITIES:
            raise ValueError("Unsupported blocking severity")


@dataclass(frozen=True)
class PolicyDecision:
    """Findings explaining a policy result."""

    blocked: tuple[Finding, ...]
    allowed: tuple[Finding, ...]

    @property
    def passed(self) -> bool:
        return not self.blocked


def evaluate_policy(
    findings: Iterable[Finding],
    policy: Policy = Policy(),
) -> PolicyDecision:
    """Evaluate every current finding, rejecting ambiguous identities."""
    if not isinstance(policy, Policy):
        raise ValueError("Expected a validated policy")

    ordered = compare_findings((), findings).added

    return PolicyDecision(
        blocked=tuple(
            finding
            for finding in ordered
            if finding.severity in policy.blocked_severities
        ),
        allowed=tuple(
            finding
            for finding in ordered
            if finding.severity not in policy.blocked_severities
        ),
    )
