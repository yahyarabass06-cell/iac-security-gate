"""Strict JSON configuration loading."""

import json
from datetime import date
from pathlib import Path

from iac_security_gate.exceptions import SecurityException
from iac_security_gate.policy import Policy


class ConfigurationError(ValueError):
    """Configuration is unreadable, invalid or unsupported."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("Duplicate configuration key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ConfigurationError("Non-standard JSON constant")


def _load_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, ValueError):
        raise ConfigurationError("Configuration could not be loaded") from None


def parse_policy(data: object) -> Policy:
    """Parse the exact policy schema, rejecting typos and duplicates."""
    expected = {"schema_version", "blocked_severities"}
    if not isinstance(data, dict) or set(data) != expected:
        raise ConfigurationError("Unexpected policy fields")

    version = data["schema_version"]
    if type(version) is not int or version != 1:
        raise ConfigurationError("Unsupported policy schema")

    severities = data["blocked_severities"]
    if (
        not isinstance(severities, list)
        or not severities
        or any(not isinstance(item, str) for item in severities)
    ):
        raise ConfigurationError("Expected a non-empty severity list")

    if len(set(severities)) != len(severities):
        raise ConfigurationError("Duplicate blocking severity")

    try:
        return Policy(blocked_severities=frozenset(severities))
    except ValueError:
        raise ConfigurationError("Invalid blocking severities") from None


def load_policy(path: Path) -> Policy:
    return parse_policy(_load_json(path))


def parse_exceptions(data: object) -> tuple[SecurityException, ...]:
    """Read exact exception scopes and canonical ISO expiration dates."""
    expected = {"schema_version", "exceptions"}
    if not isinstance(data, dict) or set(data) != expected:
        raise ConfigurationError("Unexpected exception configuration fields")

    version = data["schema_version"]
    if type(version) is not int or version != 1:
        raise ConfigurationError("Unsupported exception schema")

    entries = data["exceptions"]
    if not isinstance(entries, list):
        raise ConfigurationError("exceptions must be a list")

    fields = {
        "check_id",
        "target",
        "resource",
        "severity",
        "justification",
        "expires_on",
    }
    parsed = []
    identities = set()

    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != fields:
            raise ConfigurationError("Unexpected exception fields")

        expiration = entry["expires_on"]
        if not isinstance(expiration, str):
            raise ConfigurationError("Expected an ISO expiration date")

        try:
            expires_on = date.fromisoformat(expiration)
            if expires_on.isoformat() != expiration:
                raise ValueError("Non-canonical date")

            exception = SecurityException(
                check_id=entry["check_id"],
                target=entry["target"],
                resource=entry["resource"],
                severity=entry["severity"],
                justification=entry["justification"],
                expires_on=expires_on,
            )
        except ValueError:
            raise ConfigurationError("Invalid exception fields") from None

        if exception.identity in identities:
            raise ConfigurationError("Duplicate exception scope")

        identities.add(exception.identity)
        parsed.append(exception)

    return tuple(parsed)


def load_exceptions(path: Path) -> tuple[SecurityException, ...]:
    return parse_exceptions(_load_json(path))
