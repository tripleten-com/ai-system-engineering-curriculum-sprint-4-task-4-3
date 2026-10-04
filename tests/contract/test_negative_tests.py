"""Coldline.

===================

File:              tests/contract/test_negative_tests.py
Component:         Contract tests — The student's negative tests
Purpose:           One assessed check per public Check-list row about tests/student/
                    test_output_guardrail.py and tests/student/test_audit.py: the static guard,
                    the worker's binding to the supplied guardrail (static over both application
                    files, then observed in-process), what each file's tests actually ran, and
                    the two supplied mutations.
Interacts With:    tests/student/test_output_guardrail.py, tests/student/test_audit.py,
                    src/worker/use_cases.py, src/api/routes.py, tests/security/student_guard.py,
                    tests/security/guardrail_binding.py, tests/security/guardrail_observation.py,
                    tests/security/guardrail_mutation.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Deterministic negative tests, mutation testing, evidence from executed runs
Tools:             Python 3.12, pytest

Assessed: a fresh starter has two templates with no tests and a worker that imports no
guardrail, so every row but the static guard fails until the worker and the five tests
are written. ``poe contract`` deselects them; ``poe negative-tests-contract`` and
``poe verify`` run them (through ``tests/security/assessed_run.py``, which requires every
registered case to have executed and passed), after the output rows and the inherited
end-to-end checks and before ``poe student-tests``. The rows that run a student file are
marked ``runtime``: the audit tests verify tokens against the issuer's key set. The
static rows must pass before any row executes a file; the mutation runner refuses a file
the guard rejects, and the binding row imports the worker only after its static rules
passed, which is why this module imports nothing from ``src/`` at collection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.security import guardrail_binding, student_guard
from tests.security import guardrail_mutation as mutation
from tests.security.guardrail_binding import TASK_ROOT

pytestmark = pytest.mark.assessed


def _inventory(student_file: Path) -> mutation.Inventory:
    """Run one student file once as written, or fail the row with why it could not run."""
    try:
        return mutation.collect_inventory(student_file)
    except mutation.MutationError as exc:
        pytest.fail(str(exc))


def _verdict(name: str) -> mutation.Verdict:
    """Run one mutation against its student file, or fail the row with why it could not run."""
    try:
        return mutation.check(name)
    except mutation.MutationError as exc:
        pytest.fail(str(exc))


def test_student_files_use_only_the_harness_and_assert_each_outcome() -> None:
    """Both student files import only the harness, inspect nothing, and assert what they owe.

    Static, over each file's bytes, never an import, and the precondition of every row
    below that executes a file: the only imports are `pytest`, the annotations future,
    `typing` names and `InteractionHarness`; no name reads the environment, the filesystem,
    or a module's internals; `pytest` is used only for fixtures, marks, `param` and
    `raises`; no function takes a pytest built-in fixture as a parameter; every guardrail
    test asserts the `.state` of a record from `harness.run_worker(...)`, and every audit
    test asserts over the audit trail. `poe student-guard` is the same check, run inside
    `poe verify` before anything executes either file.
    """
    findings: list[str] = []
    for path in student_guard.STUDENT_PATHS:
        try:
            found = student_guard.findings(TASK_ROOT / path)
        except student_guard.StudentGuardError as exc:
            pytest.fail(str(exc))
        findings.extend(f"{path.as_posix()}: {item}" for item in found)
    assert findings == [], "; ".join(findings)


def test_worker_imports_the_supplied_guardrail_and_rebinds_nothing() -> None:
    """The worker hands every answer to `validate_summary` from `worker.guardrail`, and follows it.

    Static first, over the bytes of `src/worker/use_cases.py` and `src/api/routes.py`,
    never an import: the worker holds one module-level `from worker.guardrail import
    validate_summary`, no other import of that module, no definition, assignment or other
    rebinding of the name or the module, and every use of the name as the callee of a
    call; and neither file imports `pytest`, `_pytest`, `sys`, `importlib`, `builtins`,
    `gc`, `inspect`, `ctypes`, `types` or `runpy`, uses `exec`, `eval`, `compile`,
    `__import__`, `globals`, `setattr` or `delattr`, or reaches a dunder attribute
    (`__dict__`, `__globals__`, `__code__`, `__builtins__`, `__class__`). Only then is the
    worker imported and run in-process, with no stack, once per supplied response with the
    emulator's answer captured and `validate_summary` stood in for by a spy: the spy must
    be called exactly once with that exact answer text and nothing else; and again with
    the spy answering an inverted verdict (a rejection for the valid answer, the valid
    answer's validated summary for each bad answer), after which the stored record must
    follow the verdict: `NEEDS_REVIEW` with the fixed message and the code, or `COMPLETED`
    with the validated fields. This is what makes the `validation-bypass` mutation below
    target the supplied guardrail, and what a worker that parses on its own, or ignores
    the verdict, fails.
    """
    try:
        found = guardrail_binding.application_findings(TASK_ROOT)
    except guardrail_binding.GuardrailBindingError as exc:
        pytest.fail(str(exc))
    assert found == [], "; ".join(found)

    # The static rules passed, so the worker spells no door to the runner; now observe it.
    from tests.security import guardrail_observation as observation

    try:
        problems = observation.check(TASK_ROOT)
    except observation.ObservationError as exc:
        pytest.fail(str(exc))
    assert problems == [], "; ".join(problems)


@pytest.mark.runtime
def test_guardrail_file_runs_the_worker_once_per_supplied_response() -> None:
    """The guardrail file executes one test per response: valid, malformed, manipulated.

    The file is run once as written with the harness recording what each test did. A case
    is the test for a response when it ran the worker with that response and no other;
    three such cases are required. What a test names in its source counts for nothing.
    """
    inventory = _inventory(mutation.GUARDRAIL_TEST)
    problems = inventory.problems()
    assert problems == [], "; ".join(problems) + "\n\n" + inventory.describe()


@pytest.mark.runtime
def test_audit_file_has_a_trail_test_and_a_credential_test() -> None:
    """The audit file executes two tests that each run an interaction and read it as dispatcher.

    A case counts when it ran the worker and then requested its exception, with a stored
    outcome, as `dispatcher-valid`; two such cases are required. The ordered-trail test and
    the credential test are told apart by the header-leak mutation below.
    """
    inventory = _inventory(mutation.AUDIT_TEST)
    problems = inventory.problems()
    assert problems == [], "; ".join(problems) + "\n\n" + inventory.describe()


@pytest.mark.runtime
def test_bad_answer_tests_fail_when_validation_is_bypassed() -> None:
    """Both bad-answer tests fail against a copy of the worker that stores the raw answer.

    The `validation-bypass` mutation replaces the `validate_summary` call with one that
    accepts the provider's text as the summary, so a test that asserts `NEEDS_REVIEW` and
    the fixed message fails and a test that would pass either way is named.
    """
    verdict = _verdict("validation-bypass")
    assert verdict.ok, "; ".join(verdict.problems)


@pytest.mark.runtime
def test_the_credential_test_fails_when_request_headers_are_added_to_the_summary_read() -> None:
    """At least one audit test fails against a copy of the route that records the request headers.

    The `header-leak` mutation adds `dict(request.headers)`, with the `dispatcher-valid`
    bearer token, to the summary-read event; the credential test must notice. A run in
    which no audit test fails, or in which any errors, is named.
    """
    verdict = _verdict("header-leak")
    assert verdict.ok, "; ".join(verdict.problems)
