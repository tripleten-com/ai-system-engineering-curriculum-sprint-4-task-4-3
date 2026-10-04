"""Coldline.

===================

File:              tests/student/test_exception_access.py
Component:         Student tests — Exception summary access
Purpose:           Your eight access tests for GET /api/v1/exceptions/{exception_id}: one
                    allowed read and seven refusals.
Interacts With:    tests/security/harness.py, config/auth.yaml, src/api/routes.py,
                    tests/fixtures/tokens/fixtures.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Negative authorization tests, exact status assertions, 401 versus 403
Tools:             Python 3.12, pytest, httpx

This file is yours: it is one of the three files this Task permits you to change.
`poe student-tests` runs it, and `poe verify` runs it as written and again against supplied
mutations of the access rule, so every rejection test must be able to fail.

The `harness` fixture below gives each test a fresh in-process API built from `src/`, with
a memory store and the real token verifier configured from `config/auth.yaml`:

- `harness.token(name)` returns the compact token of one fixture in
  `tests/fixtures/tokens/fixtures.yaml` by its name ("dispatcher-valid", "bad-signature", ...).
- `harness.bearer_client(name)` returns an `httpx.AsyncClient` against that API with the
  fixture's token in the `Authorization` header as a bearer token:
  `async with harness.bearer_client("dispatcher-valid") as client:`.
- `harness.stored_exception()` creates one exception record with a stored summary and
  returns `(exception_id, summary)`. Call it in every test, so no test depends on an earlier
  manual run, and request `f"/api/v1/exceptions/{exception_id}"`.

The verifier fetches the issuer's key set from the `jwks_url` you configured, so start the
stack (`poe start`) before running these tests. Make every request through
`harness.bearer_client(...)`: the assessed checks run this file and record which fixture each
test really sent and which exception it requested, and that record, not the test's source,
is how they tell the allowed test from the seven rejection tests. A test counts as the
allowed test when it requests an exception with a stored summary as `dispatcher-valid` and
nothing else; it counts as the rejection test for a refused fixture when it requests such an
exception as that fixture and no other. One test per fixture, eight tests in all; a
parametrized test counts once per parameter.

Before anything runs this file, `poe student-guard` reads it (without running it) and
applies five flat rules, which `poe verify`, `poe student-tests` and the assessed checks
enforce the same way. Each rule is checked by presence, with no exceptions for how a name
came to be bound, so a rejected line is fixed by removing or renaming what it names:

- the only imports are `import pytest`, `from __future__ import annotations`,
  `from typing import ...`, and `from tests.security.harness import AccessHarness` (no
  `from pytest import ...`, and no `as` except on a typing name);
- these names are not used anywhere, not even as your own variables: `__file__`,
  `__import__`, `__builtins__`, `importlib`, `inspect`, `sys`, `os`, `subprocess`,
  `builtins`, `globals`, `locals`, `vars`, `getattr`, `setattr`, `delattr`, `eval`, `exec`,
  `compile`, `open`, `Path`, plus a few more that reach the same places (the guard's message
  names the one it found), and no `x.__anything__` or path attribute such as `x.root` or
  `x.read_text` (the `harness` fixture above is all a test needs);
- `pytest` appears only as `@pytest.fixture`, `pytest.mark.<name>`, `pytest.param`, and
  `pytest.raises`;
- no function in this file, whether a test, a fixture, a helper, or a function nested in a
  test, has a parameter named `request`, `monkeypatch`, `pytestconfig`, `capsys`, `capfd`,
  `caplog`, `tmp_path`, `tmp_path_factory`, or `recwarn`: pytest fills those with fixtures
  that reach the environment, so rename such a parameter, for example to `resp` (a local
  variable `request = f"/api/v1/exceptions/{exception_id}"` is fine);
- every test asserts the `.status_code` of a response it obtained through
  `harness.bearer_client(...)`, itself or in a helper defined in this file that it hands
  the response, and every test that expects `401` or `403` also asserts something about
  that response's body or `.text`: that the stored summary is not in it.

Tests that describe the response, as the eight marked places below ask, meet all five.
"""

import pytest

from tests.security.harness import AccessHarness


@pytest.fixture
def harness() -> AccessHarness:
    """Return a fresh in-process API, its memory store, and the token loader, for one test."""
    return AccessHarness()


# --- Test 1 of 8: `dispatcher-valid` is allowed.
# Assert status 200, the exception id, and the stored summary in the response body.


# --- Test 2 of 8: `bad-signature` is refused.
# Request an exception with a stored summary; assert the exact status from Step 2 and that
# the summary text is not in the response.


# --- Test 3 of 8: `wrong-issuer` is refused.


# --- Test 4 of 8: `wrong-audience` is refused.


# --- Test 5 of 8: `expired` is refused.


# --- Test 6 of 8: `gateway-valid` is refused.


# --- Test 7 of 8: `wrong-role` is refused.


# --- Test 8 of 8: `missing-scope` is refused.
