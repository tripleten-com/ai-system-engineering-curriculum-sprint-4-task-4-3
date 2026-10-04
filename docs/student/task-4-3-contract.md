# Task 4.3 — Output validation and audit contract

Make invalid model answers fail safely and record audit events that reconstruct one
interaction without credentials. You route the provider's raw answer through the supplied
guardrail and store the output policy's outcomes in `src/worker/use_cases.py`, record the
worker's four audit events there and the summary-read event in `src/api/routes.py`, and write
three guardrail tests in `tests/student/test_output_guardrail.py` and two audit tests in
`tests/student/test_audit.py`. You write no validator, no parser of the model's text, and no
sink; you change no other route and no supplied file.

## What is assessed, and by whom

| Assessed | By |
|---|---|
| The pull request changes only `src/worker/use_cases.py`, `src/api/routes.py`, `tests/student/test_output_guardrail.py`, and `tests/student/test_audit.py` | Automated, in this repository |
| Nothing under the four permitted files or the checks' own files changed while `poe verify` ran | Automated: `poe verify` records a hash snapshot as its first step and checks it as its last |
| Both student test files import only `pytest`, the `annotations` future, the permitted `typing` names (`Any`, `Annotated`, `Literal`, `Optional`, `Union`, `cast`, `TYPE_CHECKING`, `Final`), and `InteractionHarness`; use none of the listed environment names anywhere (`__file__`, `sys`, `importlib`, `getattr`, `open`, `Path`, any dunder, ...), and take neither `.format` nor `.format_map` from anything; use `pytest` only for fixtures, marks, `param` and `raises`; give no function a parameter named after a pytest built-in fixture; every guardrail test asserts the `.state` of a record from `harness.run_worker(...)`, and every audit test asserts over the audit trail | Automated, static, over each file's bytes, never an import (`poe student-guard`, inside `poe verify` before anything executes either file, and the first step of `poe student-tests`); the checks refuse to run a file that fails it |
| The valid response ends in `COMPLETED`, and the record holds the validated summary, `handling_class` and `next_step`, and no rejection reason | Automated, against the running stack (`poe verify`): one reading per response through the open intake, the record read through the database |
| The malformed and manipulated responses each end in `NEEDS_REVIEW`, with the output policy's fixed message as the summary, the guardrail's reason code, no validated fields, and none of the model's text in any stored field | Automated, against the running stack (`poe verify`) |
| One read of each of the three finished records leaves the four worker events in order and then one summary read, every record naming the exception; the worker's events carry the trace id the reading was submitted in and the read the trace id it was requested in; each worker event carries exactly the fields the event list permits, as scalars, with the values the checks captured independently (the reading id, the provider, the digest and length of the answer the emulator gave the request, the guardrail's decision and reason code over that answer, the stored state and summary); the read carries the caller's subject and role | Automated, against the running stack (`poe verify`), reading the trail back through the API container as `poe audit-trail` does |
| Two reads of one finished record leave two summary reads carrying two distinct trace ids, each its own request's | Automated, against the running stack (`poe verify`) |
| No audit record of any supplied response's trail contains the `dispatcher-valid` token, an `Authorization` header in any letter case, or a supplied credential value, and no summary read carries any field but `subject` and `role` | Automated, against the running stack (`poe verify`) |
| The summary-read event is recorded only for a read that returned a stored outcome, with the caller's subject and role: for each of the six states, with and without a stored summary, only `COMPLETED` and `NEEDS_REVIEW` with a summary leave exactly one; a `404` and a refused request record nothing | Automated, in-process over the real route, one case per state and summary presence, with the issuer running (`poe verify`) |
| `src/worker/use_cases.py` imports `validate_summary` from `worker.guardrail` once, at module level, rebinds neither the name nor the module, and uses the name only to call it; neither it nor `src/api/routes.py` imports `pytest`, `_pytest`, `sys`, `importlib`, `builtins`, `gc`, `inspect`, `ctypes`, `types` or `runpy`, uses `exec`, `eval`, `compile`, `__import__`, `globals`, `setattr`, `delattr` or `__builtins__`, or reaches a dunder attribute; and, run in-process once per supplied response, the worker hands `validate_summary` the provider's exact answer text, once, as its only argument, and stores the outcome the verdict names (`NEEDS_REVIEW` with the fixed message and the code for a rejection, `COMPLETED` with the validated fields for a validated summary) | Automated: the static part over both files' bytes (`poe guardrail-binding` on its own), then, only when it passes, the worker run in this process with no stack, the emulator's answers captured and `validate_summary` stood in for by a spy that first answers as the real guardrail does and then answers an inverted verdict; one assessed row of `poe negative-tests-contract` inside `poe verify` |
| The Task 2 access rule still protects `GET /api/v1/exceptions/{exception_id}`: `200` to `dispatcher-valid`, `401` to the four invalid fixtures and to a bare request, `403` to the three ungranted ones | Automated, against the running stack (`poe verify`) |
| Your guardrail file runs the worker once per supplied response, and your audit file has two tests that each run an interaction and read it as the dispatcher; both bad-answer tests fail when validation is bypassed, and the credential test fails when the request headers are added to the summary-read event | Automated, by running your files with their actions recorded and again against mutated copies of `src/` (`poe verify`) |
| `submission.yaml` still records `answers: {}` | Automated, in this repository (`poe answers`, repeated by `poe verify`) |
| What the stored records and the `poe audit-trail` output in your pull request show, and what changed between the manipulated-response records before and after your implementation | Your instructor, at the Task 4 Instructor Review; you use it again at the Project Defense |

There is no protected answer check for this Task: `answers: {}` is the whole answer sheet, and
`poe verify` is the whole automated assessment. The inherited Project 3 checks (smoke,
end-to-end workflow, queue, SLO, gate, and runbook contracts) also run inside `poe verify`, over
the supplied checkpoint, and pass as shipped.

## The supplied material

| Supplied | Where | Note |
|---|---|---|
| The output schema | `schemas/exception-summary.schema.json` | Strict: five required properties, no other, closed lists for `handling_class` and `next_step`, bounded strings. Not student-editable |
| The guardrail | `src/worker/guardrail.py` | `validate_summary(raw)` returns a `ValidatedSummary` or a `RejectedSummary` with a `code`; `REVIEW_MESSAGE` is the fixed dispatcher message; `REASON_CODES` the closed list. It rejects and never strips. Not student-editable |
| The output policy | `docs/security/output-policy.md` | The accepted outcome, the fail-safe outcome (`NEEDS_REVIEW`, the fixed message, `rejection_reason`), what `FAILED` still means, the reason codes, and the finished states |
| The audit sink | `src/common/audit.py` | `AuditSink.record(event, exception_id=..., details=...)` fills in the trace id and the time and stores the details as given; `AuditEvent` names the events; `answer_digest` is the digest the model-response event carries. The worker is composed with it as `self._audit`; the route receives it as `audit_sink`. Not student-editable |
| The event list | `docs/security/audit-events.md` | The five events in order, where each is recorded, the fields each may carry, and what none may contain |
| The audit table | `migrations/versions/` (`audit_events`), `src/adapters/persistence/audit_store.py` | Append-only, read in order by `poe audit-trail` |
| The supplied responses | `src/adapters/model/deterministic.py`, `docs/fidelity/ModelProvider.md` | `valid` (the default), `malformed` (stops partway, not JSON), `manipulated` (follows the instruction planted in `playbook-thermal-excursion`: a next step outside the list and a field the schema does not name). Selected per run by `poe scenario --response` |
| The corpus | `infra/corpus/documents.jsonl` | One supplied procedure carries the planted instruction, in the chunk the worker retrieves for the scenario's reading. Not student-editable |
| The settled Task 2 material | `config/auth.yaml`, `src/api/security/`, `tests/fixtures/tokens/`, `tests/student/test_exception_access.py` | The verifier settings, the access rule on `get_exception`, the eight token fixtures, and the eight access tests, as the reference completion left them. Not student-editable |
| The credential values | `tests/fixtures/credentials/test-values.yaml` | The development credentials this stack holds, listed once so the credential-absence checks, and your test through `harness.secret_values()`, can search for them |
| The student-test harness | `tests/security/interaction.py` | `InteractionHarness`: runs the worker in-process with the real guardrail, emulator and sink over a memory store, and the API with the real verifier; `tests/student/test_output_guardrail.py` and `tests/student/test_audit.py` document how to use it. When the assessed checks run your files, it records what each test did |
| The student-test guard | `tests/security/student_guard.py` | Reads both files as bytes, without running them, and applies five flat rules; `poe student-guard` |
| The guardrail-binding check | `tests/security/guardrail_binding.py`, `tests/security/guardrail_observation.py` | The first reads `src/worker/use_cases.py` and `src/api/routes.py` as bytes, without running them, and requires the one permitted import of `validate_summary`, no rebinding of it, and no spelled path from either file to the test runner (`poe guardrail-binding`); the second, run only after the first passes, runs the worker in-process with the provider's answers captured and the guardrail stood in for, and requires every answer to reach `validate_summary` as is and the stored outcome to follow its verdict |
| The mutations | `tests/security/guardrail_mutation.py` | `validation-bypass` over `src/worker/use_cases.py` and `header-leak` over `src/api/routes.py`, applied to temporary copies of `src/` made beside the directories it reads (`schemas/`, `config/`); `poe guardrail-mutation` |
| The assessed-module runner | `tests/security/assessed_run.py` | Runs each assessed module under pytest with a junit report and requires every registered case to have executed and passed; `poe output-contract` and `poe negative-tests-contract` go through it |
| The integrity snapshot | `tests/security/integrity.py` | Hashes your four files and the checks' own files when `poe verify` starts and compares them when it ends; `poe integrity-record` and `poe integrity-check` |

## The four steps

### Step 1 — Route every model answer through the output schema

In `WorkerApplication.process`, after the provider returns and before the `COMPLETED`
transition, call `validate_summary(answer.text)`. When it returns a `ValidatedSummary`, store
its `summary`, `handling_class` and `next_step` on the `COMPLETED` transition (the repository's
`transition` takes them as keyword arguments) and nothing else from the answer. Run `poe start`
again (the worker image carries your file), then `poe scenario`, and open the record for the
printed exception id with the `dispatcher-valid` token.

### Step 2 — Fail safely on malformed and manipulated answers

When `validate_summary` returns a `RejectedSummary`, store the output policy's outcome on the
`NEEDS_REVIEW` transition: `summary=REVIEW_MESSAGE`, `rejection_reason=verdict.code`, no
validated fields, and acknowledge the delivery as the `COMPLETED` path does. Store none of the
model's text, retry nothing, and do not move a rejected answer to `FAILED`. Run
`poe scenario --response malformed` and `poe scenario --response manipulated` and read each
stored record.

### Step 3 — Record the audit events for one interaction

In `src/worker/use_cases.py`, record `processing_requested` once the record is this attempt's,
`model_responded` when the answer comes back (digest and length, never the text),
`output_validated` or `output_rejected` with the decision, and `outcome_stored` (the state and
summary about to be stored) immediately before the terminal transition, each with the fields
`docs/security/audit-events.md` lists and no others. In
`src/api/routes.py`, inside `get_exception`, after the record is loaded and only when its state
is `COMPLETED` or `NEEDS_REVIEW` with a summary, record `summary_read` through `audit_sink` with
`principal.subject` and `principal.role`; never pass the request, its headers, or the token.
Run `poe scenario --response manipulated`, read the record once, and run
`poe audit-trail <exception_id>`.

### Step 4 — Add deterministic negative tests

Complete the three marked places in `tests/student/test_output_guardrail.py` (one test per
response, each asserting the stored state and content) and the two in
`tests/student/test_audit.py` (one ordered-trail test, one credential-absence test), as their
docstrings describe. Run `poe student-tests`, then prove the tests can fail with
`poe guardrail-mutation`.

## Commands

```shell
poe scenario --response <name>      # one reading through the stack with the named response
poe audit-trail <exception_id>      # one exception's ordered audit records
poe student-guard                   # both student files: imports, names, and asserts, without running them
poe guardrail-binding               # the worker's import of validate_summary, without running it
poe integrity-record                # hash your files and the checks' files; the first step of `poe verify`
poe integrity-check                 # compare the tree with that snapshot; the last step of `poe verify`
poe student-tests                   # the student-test guard, then your tests as written
poe student-tests-run               # the bare pytest run behind it; forwards arguments (-k <name>)
poe guardrail-mutation              # what your tests ran, then your tests against the two mutated copies of src/
poe output-contract                 # the assessed rows that read the running stack
poe negative-tests-contract         # the assessed rows about your tests
poe answers                         # the answer sheet's format only
poe verify                          # the full public path
```

Start the stack per `README.md` first; `poe verify` starts it again itself and ingests the
supplied corpus. `poe student-guard` and `poe answers` are static; the guardrail tests need no
stack; every other command above needs the running stack.

## Check-list rows and the checks that read them

| Check-list row | Check |
|---|---|
| Every model answer passes through `validate_summary` before the worker stores a summary or outcome for it | `test_valid_response_completes_with_only_the_schema_fields` together with the two `test_bad_response_needs_review_with_the_fixed_message_and_none_of_the_models_text` cases: a record that skipped the guardrail has no validated fields or keeps the model's text |
| A valid answer ends in `COMPLETED` with only the fields the schema allows | `test_valid_response_completes_with_only_the_schema_fields` |
| The malformed and manipulated responses each end in `NEEDS_REVIEW` with the output policy's fixed message and a reason code | `test_bad_response_needs_review_with_the_fixed_message_and_none_of_the_models_text[malformed]` and `[manipulated]` |
| No stored exception record for a rejected answer contains the model's text | The same two cases |
| `poe audit-trail` reconstructs one interaction with every event in `docs/security/audit-events.md`, in order, each with the exception id and the trace id of the request that recorded it | `test_the_audit_trail_reconstructs_one_interaction_in_order_with_trace_ids[valid]`, `[malformed]` and `[manipulated]`, and `test_each_summary_read_carries_its_own_requests_trace_id` |
| Every event carries the fields the event list permits and no others, with the values of the interaction it records | The three trail rows above (the worker's events) and `test_no_audit_record_contains_a_credential` (the summary read's) |
| The summary-read event records the caller's subject and role, and only for a read that returned a stored outcome | `test_summary_read_is_recorded_only_for_a_read_that_returned_a_stored_outcome[<state>-stored]`, `[<state>-no-summary]` for each of the six states, `[missing]` and `[refused]`, and the read event's fields in the trail rows |
| No audit record contains a token, an `Authorization` header, or a supplied test secret | `test_no_audit_record_contains_a_credential` |
| Every model answer reaches the supplied guardrail, by its own import | `test_worker_imports_the_supplied_guardrail_and_rebinds_nothing` (static over both application files, then the worker observed in-process: each answer handed to `validate_summary` as is, the stored outcome following the verdict), with the three stored-record rows |
| `poe student-tests` passes with one guardrail test each for the valid, malformed, and manipulated responses, and two audit tests | `test_student_files_use_only_the_harness_and_assert_each_outcome` first (static), then `test_guardrail_file_runs_the_worker_once_per_supplied_response` and `test_audit_file_has_a_trail_test_and_a_credential_test` (your files run once with their actions recorded), and `poe student-tests` inside `poe verify` |
| The bad-answer tests fail when validation is bypassed | `test_bad_answer_tests_fail_when_validation_is_bypassed` (the `validation-bypass` mutation) |
| The credential test fails when the request headers are added to the summary-read event | `test_the_credential_test_fails_when_request_headers_are_added_to_the_summary_read` (the `header-leak` mutation) |
| The Task 2 access rule still protects `GET /api/v1/exceptions/{exception_id}` | `test_the_task_2_access_rule_still_protects_the_summary_route` |
| `submission.yaml` still records `answers: {}` | `test_submission_records_no_answers`, and `poe answers` |
| The pull request modifies only `src/worker/use_cases.py`, `src/api/routes.py`, `tests/student/test_output_guardrail.py`, and `tests/student/test_audit.py` | `test_submission_change_stays_within_the_permitted_diff` in `tests/contract/test_authoring_contract.py`, and `poe submission` (the `tests/contract/submission_validation.py` module, which applies the same boundary) inside `poe verify` |

The rows that read the running stack live in `tests/contract/test_output_audit.py`
(`poe output-contract`); the rows about your worker's guardrail binding and your tests live in
`tests/contract/test_negative_tests.py` (`poe negative-tests-contract`); the last row is
`test_submission_change_stays_within_the_permitted_diff` in
`tests/contract/test_authoring_contract.py`. They are marked `assessed`: `poe contract` leaves
them out, and `poe verify` runs them through `tests/security/assessed_run.py`, which requires
every registered case to have executed and passed (a skipped or missing case fails the step).
The rows that touch the stack or run your tests are also marked `runtime`. A fresh checkout
fails most of them, which is the exercise;
`test_the_task_2_access_rule_still_protects_the_summary_route`,
`test_student_files_use_only_the_harness_and_assert_each_outcome`,
`test_submission_records_no_answers`, and the read-eligibility cases that expect no summary
read pass on it, because the settled rule is in place, the templates have no tests to check
yet, the sheet is as supplied, and a route that records nothing records nothing for them.

## What the checks verify

| Check | What it looks at |
|---|---|
| `tests/security/live_record.py` | One reading per supplied response, submitted through the open intake with the response selector, then the `exceptions` table polled inside the `postgres` container until the record is in a finished state (`COMPLETED`, `NEEDS_REVIEW`, or `FAILED`), and the record's `state`, `summary`, `handling_class`, `next_step`, `rejection_reason`, and `failure_reason` read from the same table. Nothing is read through the route the Task edits, so a wrong route cannot hide a record's state, and no read is added to its trail |
| `tests/security/trail.py` | One exception's audit records, read as `poe audit-trail --json` prints them: the event sequence (the four worker events in order, position three one of two names, then only `summary_read`, as many as the checks made); per worker event, exactly the fields `docs/security/audit-events.md` permits, every field it requires, scalars only, and the values the checks captured independently (the reading id they submitted, the provider, the digest and length of the raw answer the real emulator gives the same request, the real guardrail's decision and reason code over that answer, the state and summary the database holds); the summary read's subject and role, and, in the credential row, its permitted set; every record's trace id (the worker's events carry exactly the trace id the reading was submitted in, each read exactly its own request's, all distinct); and every record rendered whole and searched for the token, the header name, and the credential values |
| `tests/security/interaction.py` | The in-process harness the student files and the precondition row use: the worker run once per call with the real guardrail, emulator, and sink, the planted procedure as the running stack retrieves it, the API with the real verifier, and the trail from the memory store. `run_application` is the same run with the worker class and the provider as parameters, which the trusted observation uses. When the assessed checks run a student file, each worker run, each request, and what each request left in the audit store (how many summary reads the exception has and whether one holds the bearer token the request sent) is recorded against the pytest case that made it |
| `tests/security/student_guard.py` | Each student file read as bytes (UTF-8 only), parsed, never imported. Five flat rules: the four permitted import forms; the forbidden names in every position (the harness's own handles included), and `format` and `format_map` taken as attributes from anything (a format field inside a string traverses attributes the name rules cannot see; f-strings stay permitted, their expressions are inspected); the four permitted uses of `pytest`; no reserved parameter name; and, per file, the assertion it owes, with provenance tracked per parameter and per call into helpers and nested functions |
| `tests/security/guardrail_binding.py` | `src/worker/use_cases.py` and `src/api/routes.py` read as bytes, parsed, never imported. The worker: one module-level `from worker.guardrail import validate_summary` and no other import of that module; no definition, assignment, parameter, handler, capture or attribute that rebinds the name; every use of the name as the callee of a call; and none of the names that rebind a module at runtime (`importlib`, `sys.modules`, `setattr`, `exec`, ...). Both files: no import, in any form, of `pytest`, `_pytest`, `sys`, `importlib`, `builtins`, `gc`, `inspect`, `ctypes`, `types` or `runpy` or of a submodule of one; none of `exec`, `eval`, `compile`, `__import__`, `globals`, `setattr`, `delattr` or `__builtins__` in any position; and no dunder attribute access (`__dict__`, `__globals__`, `__code__`, `__builtins__`, `__class__`, or any other). The rules are syntactic: they close the spelled doors. A patch that reaches the runner only through the objects the harness hands in is not caught by them; the instructor reads the code, and the committed tree is the graded artifact |
| `tests/security/guardrail_observation.py` | Only after the binding check above passed: the worker imported and run in this process, with no stack, once per supplied response through the same harness your tests use, with the emulator wrapped so its raw answer is captured and `validate_summary` in the worker's module replaced for the run by a spy. Hand-over: the provider called once, the spy called once, handed that captured text and nothing else. Verdict followed: each response run again with the spy answering a fixed inverted verdict (a rejection for the valid answer; the validated summary the real guardrail gives the valid answer for each bad answer), after which the record's `state`, `summary`, `rejection_reason`, `handling_class` and `next_step` must be the verdict's. A worker that calls the guardrail once as a switch and parses the answer itself, or that hands the answer over and ignores what came back, is named by response |
| `tests/security/guardrail_mutation.py` | First the student-test guard above must pass, or nothing below runs. Then each file is run once as written with its actions recorded: a guardrail case counts for the response it ran the worker with, alone; an audit case counts when it ran the worker and then read its exception, with a stored outcome, as `dispatcher-valid`. Three guardrail cases and two audit cases are required. Then one rerun per mutation against a copy of `src/` made beside copies of the directories it reads at runtime (`schemas/`, `config/`), so the copy finds the same files the real tree does: `validation-bypass` replaces the `validate_summary` call with one that accepts the raw answer as the summary (both bad-answer cases must fail); `header-leak` adds the request's headers to the summary-read event, under a parameter name nothing in the route spells, so a local `request` cannot shadow it (at least one audit case must fail). Only an assertion failure counts: a case that still passes or is skipped is reported by name, and an error, or a failure whose exception is anything but `AssertionError` (read from the junit failure's type or message: a missing file or module, an `AttributeError` or `TypeError` raised inside the mutated copy, a `pytest.raises` that did not raise), makes that rerun invalid rather than a detection. Under `header-leak` a failing case is credited only when the harness recorded its read leaving a `summary_read` whose details hold the bearer token it sent; a failure for any other reason is not evidence of the leak. The copied files are read as UTF-8 with or without a BOM |
| `tests/security/assessed_run.py` | Each assessed module run under pytest with a junit report, then, outside that process, the report compared with the registered inventory of the module's cases: every registered case must appear once and have passed; a missing, skipped, errored or failed case, or an unregistered one, is named and fails the step whatever pytest's exit code was |
| `tests/security/integrity.py` | SHA-256 digests of the four student files and every file under `tests/contract/`, `tests/security/`, `src/api/security/`, `src/common/`, `schemas/`, `tests/fixtures/`, plus `src/worker/guardrail.py`, `src/adapters/model/deterministic.py`, the two security documents, the carried `config/auth.yaml` and `tests/student/test_exception_access.py`, `infra/corpus/documents.jsonl`, and `pyproject.toml`, recorded to a file outside the repository when `poe verify` starts and compared when it ends. Any file changed, added, or removed in between is named and fails the last step |
| `tests/contract/submission_validation.py` (`poe answers`, `poe submission`) and `test_submission_change_stays_within_the_permitted_diff` in `tests/contract/test_authoring_contract.py` | `submission.yaml` is one plain YAML mapping whose `answers` is present and empty; the diff from the merge base with `main` touches only the four permitted files, with no directory prefix exempted |

The runs of your files leave your files untouched: each mutation copies `src/` to a temporary
directory, changes the copy, runs your file against it, and deletes the copy; the recording
of your tests' actions goes to a temporary file the checks read and delete.

## Student-editable paths

- `src/worker/use_cases.py`
- `src/api/routes.py` (the summary-read event inside `get_exception`; the Task 2 rule stays)
- `tests/student/test_output_guardrail.py`
- `tests/student/test_audit.py`

That is the whole list. The schema, the guardrail, the output policy, the audit sink and its
store, the event list, the supplied responses, the corpus, the settled Task 2 material, the
credential values, the supplied tests, `compose.yaml`, and the workflows stay as supplied.
Before you push, run `git status` and `git diff --stat`: if anything else changed, the public
check reports the boundary violation rather than your work.
