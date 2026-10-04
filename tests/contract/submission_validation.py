"""Coldline.

===================

File:              tests/contract/submission_validation.py
Component:         Contract tests — Submission Validation
Purpose:           Validate the Task 4.3 answer sheet (answers: {}) and the four permitted paths.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest

Two entrypoints share this module. ``poe answers`` runs it with ``--format-only`` and
checks the answer sheet alone: one plain YAML mapping whose ``answers`` is present and
empty. ``poe submission`` (inside ``poe verify``) runs it in full, which adds the
permitted-path boundary: the diff from the merge base touches only
``src/worker/use_cases.py``, ``src/api/routes.py``, ``tests/student/test_output_guardrail.py``
and ``tests/student/test_audit.py``. Nothing here reads those files' content: the assessed
checks in ``test_output_audit.py`` and ``test_negative_tests.py`` do.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator

# Task 4.3's pull request changes the worker's summary path, the one route, and the two
# student test files, and nothing else: the schema, the guardrail, the output policy, the
# audit sink, the event list, the supplied responses, the corpus, the supplied tests, and
# the workflows stay as supplied.
ALLOWED_PATHS = frozenset(
    {
        "src/worker/use_cases.py",
        "src/api/routes.py",
        "tests/student/test_output_guardrail.py",
        "tests/student/test_audit.py",
    }
)
ALLOWED_PREFIXES: tuple[str, ...] = ()


_JSON_YAML_TAGS = frozenset(
    {
        "tag:yaml.org,2002:map",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
    }
)


class _RestrictedYamlLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Load the Task's small YAML profile without YAML-only conveniences."""

    def compose_node(self, parent: object, index: object) -> yaml.Node:
        # A prior anchor is already rejected below, but deny aliases directly too.
        if self.check_event(yaml.AliasEvent):
            event = self.get_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML aliases are not permitted",
                event.start_mark,
            )
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML anchors are not permitted",
                event.start_mark,
            )
        return super().compose_node(parent, index)

    def construct_object(self, node: yaml.Node, deep: bool = False) -> object:
        if node.tag not in _JSON_YAML_TAGS:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "non-JSON YAML tags are not permitted",
                node.start_mark,
            )
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, object]:
        mapping: dict[str, object] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML merge keys are not permitted",
                    key_node.start_mark,
                )
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML mapping keys must be strings",
                    key_node.start_mark,
                )
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"duplicate YAML key: {key}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


class SubmissionError(ValueError):
    """Report one actionable public-verification failure."""


def main(
    root: Path | None = None,
    *,
    changed_paths: list[str] | None = None,
    format_only: bool = False,
) -> int:
    """Validate the answer sheet, and unless ``format_only``, the permitted-path boundary.

    The optional arguments keep this entrypoint testable without changing the
    process working directory or creating a temporary Git repository.
    """
    task_root = Path.cwd() if root is None else root
    try:
        validate_submission(
            task_root / "submission.yaml",
            task_root / "docs/contracts/submission.schema.json",
            # No sample comparison for this Task. The accepted answer sheet IS the empty
            # mapping the sample shows, so a copy check would reject every correct one.
            sample_path=None,
            task_root=task_root,
        )
        if not format_only:
            validate_changed_paths(
                _changed_paths(task_root) if changed_paths is None else changed_paths
            )
    except (SubmissionError, RuntimeError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    if format_only:
        print("Task 4.3 answer format check passed.")
    else:
        print("Task 4.3 answer and permitted-path verification passed.")
    return 0


def validate_submission(
    submission_path: Path,
    schema_path: Path,
    *,
    sample_path: Path | None = None,
    task_root: Path | None = None,
) -> None:
    """Validate YAML shape, the empty mapping, the schema, and sample-copy behavior.

    ``task_root`` names the repository that owns the published contracts. It defaults
    to the answer sheet's own directory, which is correct for a student checkout. A
    curriculum-owned evaluator validating a sheet stored elsewhere passes the trusted
    Task root explicitly.
    """
    submission = _load_one_document(submission_path)
    answers = submission.get("answers") if isinstance(submission, dict) else None
    if not isinstance(answers, dict):
        raise SubmissionError("answers must be one mapping")

    # Task 4.3 has no direct answer: the work is the worker's summary path, one route, and
    # tests, and the checks read the running system and rerun those tests rather than a
    # claim about them. The mapping is therefore required to be present and empty, which is
    # a real check: it rejects an invented status field as firmly as a missing one.
    if answers:
        raise SubmissionError(
            "answers must stay an empty mapping for this Task; the guardrail call, the audit "
            f"events, and your tests are the deliverable, not a recorded claim (found: "
            f"{', '.join(sorted(answers))})"
        )

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(submission), key=lambda error: list(error.path)
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "submission"
        raise SubmissionError(f"{location}: {error.message}")

    if sample_path is not None and submission == _load_one_document(sample_path):
        raise SubmissionError("submission must not copy the fictional sample answers")


def validate_changed_paths(paths: list[str]) -> None:
    """Reject changed paths outside this Task's student-editable surfaces."""
    normalized = {PurePosixPath(path.replace("\\", "/")).as_posix() for path in paths}
    protected = sorted(
        path for path in normalized - ALLOWED_PATHS if not path.startswith(ALLOWED_PREFIXES)
    )
    if protected:
        raise SubmissionError(f"protected path changed: {', '.join(protected)}")


def _changed_paths(root: Path) -> list[str]:
    """Return changes since the commit this checkout branched from."""
    try:
        repository_root = Path(
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        ).resolve()
        if root.resolve() != repository_root:
            # The authoring snapshot is nested. Only a generated repository's
            # own history defines student changes.
            return []
        baseline = _baseline_commit(repository_root)
        result = subprocess.run(
            ["git", "diff", "--name-only", baseline],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("Git history is unavailable for protected-path validation") from exc
    return [line for line in result.stdout.splitlines() if line]


def _baseline_commit(repository_root: Path) -> str:
    """Return the commit a student's changes are measured against.

    Student work happens ahead of `main` - on a branch, or as uncommitted
    edits - and `main` itself keeps moving as this repository receives
    updates after a student has already forked from it. The protected
    boundary is therefore the commit a student actually started from
    (their merge-base with `main`), not the repository's very first
    commit, which a later update may have moved past.
    """
    for candidate in ("origin/main", "main"):
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", candidate],
            cwd=repository_root,
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            merge_base = subprocess.run(
                ["git", "merge-base", "HEAD", candidate],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            )
            return merge_base.stdout.strip()
    # No `main` branch is reachable - fall back to the repository's single
    # root commit.
    roots = subprocess.run(
        ["git", "rev-list", "--max-parents=0", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if len(roots) != 1:
        raise RuntimeError("repository must have exactly one protected root commit")
    return roots[0]


def _load_one_document(path: Path) -> dict[str, Any]:
    """Load exactly one plain JSON-compatible YAML mapping.

    A file that is not UTF-8 is reported the same way as one that is not the
    restricted YAML profile: as a public verification failure, not a traceback.
    """
    try:
        documents = list(
            yaml.load_all(path.read_text(encoding="utf-8"), Loader=_RestrictedYamlLoader)
        )
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise SubmissionError(f"{path.name} must contain UTF-8 restricted YAML") from exc
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise SubmissionError(f"{path.name} must contain exactly one YAML mapping")
    return documents[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the Task 4.3 submission.")
    parser.add_argument(
        "--format-only",
        action="store_true",
        help="check the answer sheet's format only (what `poe answers` runs)",
    )
    arguments = parser.parse_args()
    raise SystemExit(main(format_only=arguments.format_only))
