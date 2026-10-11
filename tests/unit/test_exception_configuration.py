"""Validate JSON exception scopes and expiration syntax."""

from datetime import date
from pathlib import Path

import pytest

from iac_security_gate.configuration import (
    ConfigurationError,
    load_exceptions,
    parse_exceptions,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def entry():
    return {
        "check_id": "AWS-0107",
        "target": "main.tf",
        "resource": "aws_security_group.lab_ssh",
        "severity": "HIGH",
        "justification": "Synthetic exception for tests.",
        "expires_on": "2026-10-12",
    }


def test_default_exception_file_is_empty():
    assert load_exceptions(ROOT / "config" / "exceptions.json") == ()


def test_valid_exception_loads(entry):
    result = parse_exceptions({"schema_version": 1, "exceptions": [entry]})
    assert len(result) == 1
    assert result[0].expires_on == date(2026, 10, 12)
    assert result[0].justification == entry["justification"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expires_on", None),
        ("expires_on", "20261012"),
        ("expires_on", "2026-02-30"),
        ("expires_on", "2026-10-12T00:00:00"),
        ("resource", None),
        ("justification", ""),
        ("severity", "URGENT"),
        ("target", "../main.tf"),
    ],
)
def test_invalid_exception_entry(entry, field, value):
    entry[field] = value
    with pytest.raises(ConfigurationError):
        parse_exceptions({"schema_version": 1, "exceptions": [entry]})


def test_missing_field_is_rejected(entry):
    entry.pop("justification")
    with pytest.raises(ConfigurationError):
        parse_exceptions({"schema_version": 1, "exceptions": [entry]})


def test_unknown_field_is_rejected(entry):
    entry["enabled"] = True
    with pytest.raises(ConfigurationError):
        parse_exceptions({"schema_version": 1, "exceptions": [entry]})


def test_duplicate_scope_is_rejected(entry):
    with pytest.raises(ConfigurationError):
        parse_exceptions(
            {
                "schema_version": 1,
                "exceptions": [entry, dict(entry)],
            }
        )


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        {"schema_version": True, "exceptions": []},
        {"schema_version": 2, "exceptions": []},
        {"schema_version": 1, "exceptions": None},
        {"schema_version": 1, "exceptions": [None]},
    ],
)
def test_invalid_exception_configuration(data):
    with pytest.raises(ConfigurationError):
        parse_exceptions(data)


def test_expired_exception_remains_available_for_audit(entry):
    entry["expires_on"] = "2020-01-01"
    result = parse_exceptions({"schema_version": 1, "exceptions": [entry]})
    assert not result[0].is_active_on(date(2026, 10, 11))
