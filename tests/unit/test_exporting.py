"""Check exclusive publication and cleanup after publication failures."""

import os

import pytest

from iac_security_gate.exporting import write_new_report


def test_new_report_contains_complete_content(tmp_path):
    path = tmp_path / "report.json"
    write_new_report(path, '{"gate": "block"}\n')
    assert path.read_text() == '{"gate": "block"}\n'
    assert list(tmp_path.iterdir()) == [path]


def test_existing_report_is_preserved(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("original")
    with pytest.raises(FileExistsError):
        write_new_report(path, "replacement")
    assert path.read_text() == "original"
    assert list(tmp_path.iterdir()) == [path]


def test_existing_symlink_is_preserved(tmp_path):
    original = tmp_path / "original.json"
    original.write_text("original")
    link = tmp_path / "report.json"
    link.symlink_to(original)
    with pytest.raises(FileExistsError):
        write_new_report(link, "replacement")
    assert link.is_symlink()
    assert original.read_text() == "original"


def test_publication_failure_cleans_temporary_file(tmp_path, monkeypatch):
    def fail_link(*args, **kwargs):
        raise OSError("Synthetic filesystem failure")

    monkeypatch.setattr(os, "link", fail_link)
    with pytest.raises(OSError):
        write_new_report(tmp_path / "report.json", "content")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission check")
def test_report_is_owner_only(tmp_path):
    path = tmp_path / "report.json"
    write_new_report(path, "content")
    assert path.stat().st_mode & 0o777 == 0o600
