"""Publish complete reports without overwriting existing paths."""

import os
import tempfile
from pathlib import Path


def write_new_report(path: Path, content: str) -> None:
    """Publish through an exclusive hard link in a user-controlled directory."""
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".iac-report-",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())

        # Both paths are in the same directory/filesystem.
        # An existing destination, including a symlink, causes failure.
        os.link(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
