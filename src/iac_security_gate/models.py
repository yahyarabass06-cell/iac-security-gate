"""Validated, scanner-independent security findings."""

from dataclasses import dataclass
from pathlib import PurePosixPath

SEVERITIES = frozenset({"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True)
class Finding:
    """A failed security check and its source evidence."""

    check_id: str
    target: str
    severity: str
    title: str
    description: str
    resource: str | None = None
    start_line: int | None = None
    end_line: int | None = None

    def __post_init__(self) -> None:
        for name in ("check_id", "target", "severity", "title"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            if value != value.strip():
                raise ValueError(f"{name} must not have surrounding whitespace")

        if self.severity not in SEVERITIES:
            raise ValueError("Unsupported severity")

        if not isinstance(self.description, str):
            raise ValueError("description must be a string")

        path = PurePosixPath(self.target)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in self.target
            or ":" in self.target
            or "\x00" in self.target
            or self.target == "."
            or path.as_posix() != self.target
        ):
            raise ValueError("target must be a canonical relative POSIX file path")

        if self.resource is not None:
            if (
                not isinstance(self.resource, str)
                or not self.resource.strip()
                or self.resource != self.resource.strip()
            ):
                raise ValueError("resource must be a non-empty string or None")

        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("Source line bounds must both be present or absent")

        if self.start_line is not None:
            for line in (self.start_line, self.end_line):
                if type(line) is not int or line < 1:
                    raise ValueError("Source lines must be positive integers")
            if self.end_line < self.start_line:
                raise ValueError("end_line must not precede start_line")

    @property
    def identity(self) -> tuple[str, str, str | None]:
        """Identify a finding independently of severity and source line numbers."""
        return self.check_id, self.target, self.resource
