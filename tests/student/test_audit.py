"""Coldline.

===================

File:              tests/student/test_audit.py
Component:         Student tests — Audit trail
Purpose:           Your two audit tests: one interaction leaves every listed event in order,
                    and no audit record contains a credential.
Interacts With:    tests/security/interaction.py, src/worker/use_cases.py, src/api/routes.py,
                    src/common/audit.py, docs/security/audit-events.md,
                    tests/fixtures/tokens/fixtures.yaml, tests/fixtures/credentials/test-values.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Audit trail as evidence, credentials never recorded, deterministic tests
Tools:             Python 3.12, pytest, httpx

This file is yours: it is one of the four files this Task permits you to change.
`poe student-tests` runs it, and `poe verify` runs it as written and again against a
supplied mutation of the route (the request headers, with the `dispatcher-valid` bearer
token, added to the summary-read event), so the credential test must be able to fail.

The `harness` fixture below runs the real worker and the real API in this process, over one
memory store and one memory audit sink, with the real token verifier configured from
`config/auth.yaml`:

- `record = await harness.run_worker(response)` processes one fresh exception once with
  the named emulator response (`"valid"`, `"malformed"`, or `"manipulated"`) and returns
  the stored record; `record.exception_id` is the id to read and to look the trail up by.
- `harness.bearer_client(name)` returns an `httpx.AsyncClient` against the in-process API
  with that token fixture as a bearer token:
  `async with harness.bearer_client("dispatcher-valid") as client:` then
  `await client.get(f"/api/v1/exceptions/{record.exception_id}")`. Read the record once.
- `harness.audit_trail(exception_id)` returns the audit records of that exception, oldest
  first; each has `.event`, `.exception_id`, `.trace_id`, and `.details` (a dict).
- `harness.audit_text(exception_id)` returns the same records as text, one JSON line per
  record, every key and value included: search it for what must not be there.
- `harness.token(name)` returns one fixture's compact token, and `harness.secret_values()`
  the supplied credential values (`tests/fixtures/credentials/test-values.yaml`). Load both
  through these; never paste a token or a secret value into this file.

The verifier fetches the issuer's key set from the configured `jwks_url`, so start the stack
(`poe start`) before running these tests. Each test runs its own interaction and reads it as
`dispatcher-valid`: the assessed checks run this file and record what each test did, and a
test counts as an audit test when it ran the worker and then read the exception with a
stored outcome as `dispatcher-valid`. Two tests in all.

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
- every test asserts over the audit trail: over `harness.audit_trail(...)` or
  `harness.audit_text(...)`, a value bound from one, or a helper defined in this file that
  it hands one.

Tests that describe the trail, as the two marked places below ask, meet all five.
"""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API, with their own memory store and audit sink."""
    return InteractionHarness()


# --- Test 1 of 2: one interaction leaves every listed event, in order.
# Run the worker once, read the record once as `dispatcher-valid`, then assert that the
# trail's events are exactly the four worker events of docs/security/audit-events.md in
# their order (position three is `output_validated` or `output_rejected`, depending on the
# response you chose), followed by your `summary_read`; that every record names the
# exception id; and that the read event's details carry the caller's subject and role.


# --- Test 2 of 2: no audit record contains a credential.
# Run the worker once and read the record once as `dispatcher-valid`, then assert that the
# trail's text contains neither the `dispatcher-valid` token (`harness.token(...)`), nor the
# header name `authorization` in any letter case, nor any value from
# `harness.secret_values()`.
