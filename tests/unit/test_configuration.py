"""Validate policy configuration without silent fallbacks."""

from pathlib import Path

import pytest

from iac_security_gate.configuration import (
    ConfigurationError,
    load_policy,
    parse_policy,
)

ROOT = Path(__file__).resolve().parents[2]


def test_repository_policy_loads():
    policy = load_policy(ROOT / "config" / "policy.json")
    assert policy.blocked_severities == frozenset({"HIGH", "CRITICAL", "UNKNOWN"})


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {},
        {"schema_version": 1},
        {"schema_version": True, "blocked_severities": ["HIGH"]},
        {"schema_version": 2, "blocked_severities": ["HIGH"]},
        {"schema_version": 1, "blocked_severities": []},
        {"schema_version": 1, "blocked_severities": "HIGH"},
        {"schema_version": 1, "blocked_severities": [None]},
        {"schema_version": 1, "blocked_severities": [["HIGH"]]},
        {"schema_version": 1, "blocked_severities": ["URGENT"]},
        {"schema_version": 1, "blocked_severities": ["HIGH", "HIGH"]},
        {
            "schema_version": 1,
            "blocked_severities": ["HIGH"],
            "unexpected": True,
        },
    ],
)
def test_invalid_policy_configuration(data):
    with pytest.raises(ConfigurationError):
        parse_policy(data)


@pytest.mark.parametrize(
    "content",
    [
        "{",
        '{"schema_version": 1, "schema_version": 1}',
        '{"schema_version": NaN}',
    ],
)
def test_invalid_configuration_json(tmp_path, content):
    path = tmp_path / "policy.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_policy(path)


def test_missing_configuration_file(tmp_path):
    with pytest.raises(ConfigurationError):
        load_policy(tmp_path / "missing.json")
