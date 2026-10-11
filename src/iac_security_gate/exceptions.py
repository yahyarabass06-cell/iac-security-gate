"""Explicitly scoped and time-limited security exceptions."""

from dataclasses import dataclass
from datetime import date

from iac_security_gate.models import Finding


@dataclass(frozen=True)
class SecurityException:
    """An exception for one finding identity and one exact severity."""

    check_id: str
    target: str
    resource: str
    severity: str
    justification: str
    expires_on: date

    def __post_init__(self) -> None:
        if not isinstance(self.resource, str) or not self.resource.strip():
            raise ValueError("An explicit resource is required")

        # Reuse the finding model's identifier, path and severity validation.
        Finding(
            check_id=self.check_id,
            target=self.target,
            resource=self.resource,
            severity=self.severity,
            title="Exception scope validation",
            description="",
        )

        if not isinstance(self.justification, str) or not self.justification.strip():
            raise ValueError("A non-empty justification is required")

        if type(self.expires_on) is not date:
            raise ValueError("expires_on must be a date without a time component")

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.check_id, self.target, self.resource

    def is_active_on(self, today: date) -> bool:
        """Expiration is exclusive; callers supply the evaluation date."""
        if type(today) is not date:
            raise ValueError("Evaluation date must be a date")
        return today < self.expires_on

    def matches(self, finding: Finding) -> bool:
        """Match exact scope and severity without evaluating expiration."""
        if not isinstance(finding, Finding):
            raise ValueError("Expected a validated finding")
        return self.identity == finding.identity and self.severity == finding.severity
