"""Coldline.

===================

File:              tests/contract/test_submission.py
Component:         Contract tests — Test Submission
Purpose:           Tests for the public answer and path checks for this Task's submission.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest
"""

from pathlib import Path

import pytest
import yaml

from tests.contract.submission_validation import (
    SubmissionError,
    _load_one_document,
    main,
    validate_changed_paths,
    validate_submission,
)

ROOT = Path(__file__).parents[2]
SCHEMA = ROOT / "docs/contracts/submission.schema.json"
TEMPLATE = ROOT / "tests/fixtures/submission-template.yaml"
PERMITTED = [
    "src/worker/use_cases.py",
    "src/api/routes.py",
    "tests/student/test_output_guardrail.py",
    "tests/student/test_audit.py",
]


def _task_root(tmp_path: Path, submission_text: str) -> Path:
    """Stage a minimal Task root the public verifier can validate."""
    (tmp_path / "docs/contracts").mkdir(parents=True)
    (tmp_path / "submission.yaml").write_text(submission_text, encoding="utf-8")
    (tmp_path / "submission-sample.yaml").write_text(
        (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs/contracts/submission.schema.json").write_text(
        SCHEMA.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return tmp_path


def test_shipped_answer_sheet_passes_as_it_stands(tmp_path: Path) -> None:
    """Accept the shipped empty mapping, which is this Task's correct answer sheet."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    validate_submission(root / "submission.yaml", SCHEMA)


def test_public_entrypoint_accepts_the_shipped_sheet(tmp_path: Path) -> None:
    """The public verifier must not require an answer this Task does not ask for."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    assert main(root, changed_paths=[]) == 0
    assert main(root, changed_paths=[], format_only=True) == 0


def test_public_entrypoint_accepts_the_four_permitted_paths(tmp_path: Path) -> None:
    """A diff over exactly the four student files passes the whole public path."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    assert main(root, changed_paths=list(PERMITTED)) == 0


def test_public_entrypoint_reports_a_protected_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A change to the supplied guardrail is named, not silently accepted."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    assert main(root, changed_paths=["src/worker/guardrail.py"]) == 1
    assert "protected path changed: src/worker/guardrail.py" in capsys.readouterr().err


def test_invented_status_field_is_rejected(tmp_path: Path) -> None:
    """A self-reported status is not evidence, and the schema says so."""
    root = _task_root(tmp_path, yaml.safe_dump({"answers": {"guardrail_called": True}}))

    with pytest.raises(SubmissionError, match="empty mapping"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_invented_test_report_field_is_rejected(tmp_path: Path) -> None:
    """An answer sheet is not a place to assert that tests passed."""
    root = _task_root(
        tmp_path, yaml.safe_dump({"answers": {"tests_passed": "all five negative tests green"}})
    )

    with pytest.raises(SubmissionError, match="empty mapping"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_missing_answers_mapping_is_rejected(tmp_path: Path) -> None:
    """An empty mapping is required, not merely tolerated."""
    root = _task_root(tmp_path, "task: 4.3\n")

    with pytest.raises(SubmissionError, match="answers must be one mapping"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_only_the_four_permitted_paths_may_change() -> None:
    """The worker's summary path, the one route, and the two student test files; nothing else."""
    validate_changed_paths(list(PERMITTED))

    for protected in (
        "src/worker/guardrail.py",
        "schemas/exception-summary.schema.json",
        "src/common/audit.py",
        "src/adapters/model/deterministic.py",
        "src/adapters/persistence/audit_store.py",
        "src/api/security/access.py",
        "config/auth.yaml",
        "infra/corpus/documents.jsonl",
        "docs/security/output-policy.md",
        "docs/security/audit-events.md",
        "tests/fixtures/credentials/test-values.yaml",
        "tests/fixtures/tokens/fixtures.yaml",
        "tests/security/guardrail_mutation.py",
        "tests/contract/test_output_audit.py",
        "tests/student/test_exception_access.py",
        "tests/student/test_student_boundary.py",
        ".github/workflows/task.yml",
        "compose.yaml",
        "pyproject.toml",
        "README.md",
        "submission.yaml",
    ):
        with pytest.raises(SubmissionError, match="protected path changed"):
            validate_changed_paths([protected])


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "answers: {value: first, value: second}\n",
        "answers: &answer {}\n",
        "answers: *missing\n",
        "answers: {<<: {value: fictional}}\n",
        "answers: {value: 2026-09-04}\n",
        "answers: {value: !custom fictional}\n",
        "answers: {1: fictional}\n",
    ],
    ids=["duplicate-key", "anchor", "alias", "merge-key", "date", "custom-tag", "non-string-key"],
)
def test_non_json_yaml_constructs_are_rejected(tmp_path: Path, unsafe_text: str) -> None:
    """Reject restricted syntax before schema validation can mask a parser defect."""
    submission = tmp_path / "submission.yaml"
    submission.write_text(unsafe_text, encoding="utf-8")

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_multiple_yaml_documents_are_rejected(tmp_path: Path) -> None:
    """A second document cannot supply or replace the answer mapping."""
    submission = tmp_path / "submission.yaml"
    submission.write_text("answers: {}\n---\nanswers: {}\n", encoding="utf-8")

    with pytest.raises(SubmissionError, match="exactly one YAML mapping"):
        _load_one_document(submission)


def test_a_sheet_that_is_not_utf_8_is_a_submission_error(tmp_path: Path) -> None:
    """A sheet saved in another encoding gets the public error, not a Python traceback."""
    submission = tmp_path / "submission.yaml"
    submission.write_bytes("answers: {}\n".encode("utf-16"))

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)
