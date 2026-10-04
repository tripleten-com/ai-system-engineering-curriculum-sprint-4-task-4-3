"""Coldline.

===================

File:              tests/unit/security/test_integrity.py
Component:         Unit tests — Verification integrity snapshot
Purpose:           Prove the snapshot names every file changed, added, or removed while `poe
                    verify` ran, including by a student test's teardown.
Interacts With:    tests/security/integrity.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Trusted bookends, content hashes, tamper evidence
Tools:             Python 3.12, pytest

The tests build a small tree shaped like the Task's trusted paths under ``tmp_path`` and
point the snapshot at a file beside it, so nothing here touches the real checkout or the
system temporary directory. One test runs a real pytest subprocess over a student file
whose session teardown rewrites the worker module, the scenario the check exists for.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.security import integrity

TRUSTED_TREE = {
    "pyproject.toml": "[tool.poe.tasks]\nverify = []\n",
    "src/worker/use_cases.py": "def process():\n    return validate_summary('x')\n",
    "src/api/routes.py": "def create_app():\n    return None\n",
    "tests/student/test_output_guardrail.py": "def test_student():\n    pass\n",
    "tests/student/test_audit.py": "def test_trail():\n    pass\n",
    "tests/contract/test_output_audit.py": "def test_row():\n    pass\n",
    "tests/security/guardrail_mutation.py": "MUTATIONS = ()\n",
    "src/api/security/access.py": "STATUS_BY_KIND = {}\n",
    "src/common/audit.py": "class AuditSink: ...\n",
    "src/worker/guardrail.py": "REVIEW_MESSAGE = 'x'\n",
    "src/adapters/model/deterministic.py": "RESPONSES = ()\n",
    "schemas/exception-summary.schema.json": "{}\n",
    "docs/security/output-policy.md": "# policy\n",
    "docs/security/audit-events.md": "# events\n",
    "tests/fixtures/credentials/test-values.yaml": "values: {}\n",
    "tests/fixtures/tokens/fixtures.yaml": "fixtures: {}\n",
    "config/auth.yaml": "auth: {}\n",
    "tests/student/test_exception_access.py": "def test_access():\n    pass\n",
    "infra/corpus/documents.jsonl": "{}\n",
}
# The credential values are covered twice (under `tests/fixtures/` and by name) and listed
# once, at their first position.
EXPECTED_ORDER = [
    "src/worker/use_cases.py",
    "src/api/routes.py",
    "tests/student/test_output_guardrail.py",
    "tests/student/test_audit.py",
    "tests/contract/test_output_audit.py",
    "tests/security/guardrail_mutation.py",
    "src/api/security/access.py",
    "src/common/audit.py",
    "src/worker/guardrail.py",
    "src/adapters/model/deterministic.py",
    "schemas/exception-summary.schema.json",
    "docs/security/output-policy.md",
    "docs/security/audit-events.md",
    "tests/fixtures/credentials/test-values.yaml",
    "tests/fixtures/tokens/fixtures.yaml",
    "config/auth.yaml",
    "tests/student/test_exception_access.py",
    "infra/corpus/documents.jsonl",
    "pyproject.toml",
]

TAMPERING_STUDENT_FILE = '''"""A student file whose session teardown rewrites the worker module."""

from pathlib import Path

import pytest

USE_CASES = Path(__file__).resolve().parents[2] / "src/worker/use_cases.py"


@pytest.fixture(scope="session")
def harness():
    yield "harness"
    # Teardown: by now every assertion has run; rewrite the worker behind the checks.
    USE_CASES.write_text("def process():\\n    return None\\n", encoding="utf-8")


def test_valid(harness):
    assert harness == "harness"
'''


def _tree(root: Path) -> None:
    """Write the small trusted tree, plus noise the snapshot must ignore."""
    for relative, text in TRUSTED_TREE.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    cache = root / "tests/security/__pycache__"
    cache.mkdir()
    (cache / "guardrail_mutation.cpython-312.pyc").write_bytes(b"\x00")
    (root / "README.md").write_text("not covered\n", encoding="utf-8")


def test_the_snapshot_covers_the_trusted_paths_and_skips_caches(tmp_path: Path) -> None:
    """Every file under the trusted paths is hashed; `__pycache__` and other files are not."""
    _tree(tmp_path)

    files = [path.as_posix() for path in integrity.trusted_files(tmp_path)]

    assert files == EXPECTED_ORDER
    digests = integrity.snapshot(tmp_path)
    assert set(digests) == set(files)
    assert all(len(digest) == 64 for digest in digests.values())


def test_the_trusted_paths_name_the_four_student_files_first() -> None:
    """The snapshot starts with the Task's four permitted files, then the checks' material."""
    assert integrity.TRUSTED_PATHS[:4] == (
        "src/worker/use_cases.py",
        "src/api/routes.py",
        "tests/student/test_output_guardrail.py",
        "tests/student/test_audit.py",
    )
    for trusted in (
        "tests/contract/",
        "tests/security/",
        "src/common/",
        "src/worker/guardrail.py",
        "schemas/",
        "tests/fixtures/",
        "tests/fixtures/credentials/test-values.yaml",
        "config/auth.yaml",
        "tests/student/test_exception_access.py",
        "infra/corpus/documents.jsonl",
        "pyproject.toml",
    ):
        assert trusted in integrity.TRUSTED_PATHS, trusted
    assert len(integrity.TRUSTED_PATHS) == len(set(integrity.TRUSTED_PATHS))


def test_a_file_covered_twice_is_hashed_once(tmp_path: Path) -> None:
    """The credential values, under `tests/fixtures/` and named on their own, appear once."""
    _tree(tmp_path)

    files = [path.as_posix() for path in integrity.trusted_files(tmp_path)]

    assert files.count("tests/fixtures/credentials/test-values.yaml") == 1
    assert len(files) == len(set(files))
    (tmp_path / "config/auth.yaml").write_text("auth: {changed: true}\n", encoding="utf-8")
    before = dict.fromkeys(EXPECTED_ORDER, "x")
    after = {**before, "config/auth.yaml": "y"}
    assert integrity.compare(before, after) == ["config/auth.yaml changed during verification"]


def test_compare_names_changed_added_and_removed_files() -> None:
    """One finding per file, in path order, saying which of the three happened."""
    before = {"a.py": "1", "b.py": "2", "c.py": "3"}
    after = {"a.py": "1", "b.py": "9", "d.py": "4"}

    assert integrity.compare(before, after) == [
        "b.py changed during verification",
        "c.py was removed during verification",
        "d.py was added during verification",
    ]
    assert integrity.compare(before, dict(before)) == []


def test_a_student_teardown_that_rewrites_the_worker_module_is_named(tmp_path: Path) -> None:
    """Record, run a student file whose session teardown edits use_cases.py, check: it is named.

    The student tests pass as written, and only after the last assertion does the
    teardown strip the guardrail call. The snapshot recorded before the run disagrees
    with the tree after it, and the check says which file.
    """
    _tree(tmp_path)
    student = tmp_path / "tests/student/test_output_guardrail.py"
    student.write_text(TAMPERING_STUDENT_FILE, encoding="utf-8")
    snapshot = tmp_path.parent / f"{tmp_path.name}-snapshot.json"

    recorded = integrity.record(tmp_path, snapshot)
    assert recorded == snapshot and snapshot.is_file()
    before = (tmp_path / "src/worker/use_cases.py").read_text(encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-m", "pytest", str(student), "-q", "-p", "no:cacheprovider"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (tmp_path / "src/worker/use_cases.py").read_text(encoding="utf-8") != before

    assert integrity.check(tmp_path, snapshot) == [
        "src/worker/use_cases.py changed during verification",
    ]
    assert not snapshot.exists(), "the snapshot is consumed by the check"


def test_an_unchanged_tree_passes_and_the_snapshot_is_consumed(tmp_path: Path) -> None:
    """Record then check with nothing in between: no findings, and the snapshot is gone."""
    _tree(tmp_path)
    snapshot = tmp_path.parent / f"{tmp_path.name}-clean.json"

    integrity.record(tmp_path, snapshot)
    assert integrity.check(tmp_path, snapshot) == []
    assert not snapshot.exists()


def test_a_missing_foreign_or_malformed_snapshot_is_a_tooling_error(tmp_path: Path) -> None:
    """No snapshot, another checkout's snapshot, or an unreadable one: an error, not a pass."""
    _tree(tmp_path)
    snapshot = tmp_path.parent / f"{tmp_path.name}-errors.json"

    with pytest.raises(integrity.IntegrityError, match="no integrity snapshot"):
        integrity.check(tmp_path, snapshot)

    other = tmp_path / "other"
    other.mkdir()
    _tree(other)
    integrity.record(other, snapshot)
    with pytest.raises(integrity.IntegrityError, match="was recorded for"):
        integrity.check(tmp_path, snapshot)

    snapshot.write_text("{not json", encoding="utf-8")
    with pytest.raises(integrity.IntegrityError, match="could not be read"):
        integrity.check(tmp_path, snapshot)
    snapshot.write_text('{"root": "x", "files": "nope"}', encoding="utf-8")
    with pytest.raises(integrity.IntegrityError, match="no file digests"):
        integrity.check(tmp_path, snapshot)


def test_the_snapshot_lives_outside_the_repository_per_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The default path is in the system temporary directory and differs per checkout root."""
    monkeypatch.delenv(integrity.SNAPSHOT_VARIABLE, raising=False)
    first = integrity.snapshot_path(tmp_path / "one")
    second = integrity.snapshot_path(tmp_path / "two")

    assert first != second
    assert first.parent == second.parent
    assert not first.is_relative_to(tmp_path)
    assert first.name.startswith("coldline-verify-") and first.suffix == ".json"

    monkeypatch.setenv(integrity.SNAPSHOT_VARIABLE, str(tmp_path / "override.json"))
    assert integrity.snapshot_path(tmp_path / "one") == tmp_path / "override.json"


def test_the_command_line_records_then_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`record` exits 0 with the count; `check` exits 1 naming a change, 2 without a snapshot."""
    _tree(tmp_path)
    monkeypatch.setenv(integrity.SNAPSHOT_VARIABLE, str(tmp_path.parent / f"{tmp_path.name}.json"))

    assert integrity.main(["check", "--root", str(tmp_path)]) == 2
    assert "no integrity snapshot" in capsys.readouterr().err

    assert integrity.main(["record", "--root", str(tmp_path)]) == 0
    assert f"recorded {len(EXPECTED_ORDER)} trusted files" in capsys.readouterr().out
    (tmp_path / "tests/security/guardrail_mutation.py").write_text(
        "MUTATIONS = ('x',)\n", encoding="utf-8"
    )
    assert integrity.main(["check", "--root", str(tmp_path)]) == 1
    assert (
        "- tests/security/guardrail_mutation.py changed during verification"
        in capsys.readouterr().err
    )

    assert integrity.main(["record", "--root", str(tmp_path)]) == 0
    assert integrity.main(["check", "--root", str(tmp_path)]) == 0
    assert "every trusted file is as it was" in capsys.readouterr().out
