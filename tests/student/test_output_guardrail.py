"""Coldline.

===================

File:              tests/student/test_output_guardrail.py
Component:         Student tests — Output guardrail
Purpose:           Your three guardrail tests: the valid answer is stored, and the malformed and
                    manipulated answers each end in NEEDS_REVIEW with the fixed message.
Interacts With:    tests/security/interaction.py, src/worker/use_cases.py,
                    src/worker/guardrail.py, schemas/exception-summary.schema.json,
                    docs/security/output-policy.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Deterministic negative tests, fail-safe outcomes, supplied bad answers
Tools:             Python 3.12, pytest

This file is yours: it is one of the four files this Task permits you to change.
`poe student-tests` runs it, and `poe verify` runs it as written and again against a
supplied mutation of the worker (the guardrail call bypassed), so the two bad-answer tests
must be able to fail.

The `harness` fixture below runs the real worker in this process, with the real guardrail,
the real model emulator (no latency), the real audit sink over a memory store, and the
supplied procedure the running stack retrieves for the scenario's reading:

- `record = await harness.run_worker(response)` creates one fresh exception for the
  scenario's reading, processes it once with the named emulator response (`"valid"`,
  `"malformed"`, or `"manipulated"`), and returns the stored record. Assert the record's
  `state` (compare it with the state name, `record.state == "NEEDS_REVIEW"`), `summary`,
  `handling_class`, `next_step`, and `rejection_reason`.
- `harness.review_message` is the output policy's fixed dispatcher message, and
  `harness.reason_codes` the guardrail's reason codes (a stored code may carry a schema
  field after a colon, `value_not_permitted:next_step`; `code.split(":")[0]` is the code).
- `harness.responses` names the three responses.

These tests need no running stack: nothing here reads the API. Call `run_worker` once per
test, with one response, so each test is the test for that response: the assessed checks
run this file and record which response each test ran the worker with, and that record,
not the test's name, is how they tell the three tests apart. Three tests in all, one per
response; a parametrized test counts once per parameter.

Before anything runs this file, `poe student-guard` reads it (without running it) and
applies five flat rules, which `poe verify`, `poe student-tests` and the assessed checks
enforce the same way. Each rule is checked by presence, with no exceptions for how a name
came to be bound, so a rejected line is fixed by removing or renaming what it names:

- the only imports are `import pytest`, `from __future__ import annotations`,
  `from typing import <name>` for `Any`, `Annotated`, `Literal`, `Optional`, `Union`,
  `cast`, `TYPE_CHECKING` or `Final`, and
  `from tests.security.interaction import InteractionHarness` (no `from pytest import ...`,
  no other `typing` name, and no `as` except on one of those typing names);
- these names are not used anywhere, not even as your own variables: `__file__`,
  `__import__`, `__builtins__`, `importlib`, `inspect`, `sys`, `os`, `subprocess`,
  `builtins`, `globals`, `locals`, `vars`, `getattr`, `setattr`, `delattr`, `eval`, `exec`,
  `compile`, `open`, `Path`, plus a few more that reach the same places (the guard's message
  names the one it found), and no `x.__anything__` or harness internal such as
  `x.repository` or `x.root` (the methods above are all a test needs);
- `pytest` appears only as `@pytest.fixture`, `pytest.mark.<name>`, `pytest.param`, and
  `pytest.raises`;
- no function in this file, whether a test, a fixture, a helper, or a function nested in a
  test, has a parameter named `request`, `monkeypatch`, `pytestconfig`, `capsys`, `capfd`,
  `caplog`, `tmp_path`, `tmp_path_factory`, or `recwarn`: pytest fills those with fixtures
  that reach the environment, so rename such a parameter, for example to `resp`;
- every test asserts the `.state` of a record it obtained from `harness.run_worker(...)`,
  itself or in a helper defined in this file that it hands the record.

Tests that describe the stored record, as the three marked places below ask, meet all five.
"""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API, with their own memory store and audit sink."""
    return InteractionHarness()


# --- Test 1 of 3: the valid response.
# Run the worker with "valid"; assert state COMPLETED, and that the stored summary,
# handling_class and next_step are the validated schema fields (not empty, not the fixed
# message), and that rejection_reason is None.


# --- Test 2 of 3: the malformed response.
# Run the worker with "malformed"; assert state NEEDS_REVIEW, summary == the fixed message,
# rejection_reason is one of the reason codes, and handling_class and next_step are None, so
# none of the model's text was stored.


# --- Test 3 of 3: the manipulated response.
# Run the worker with "manipulated"; assert the same fail-safe outcome.
