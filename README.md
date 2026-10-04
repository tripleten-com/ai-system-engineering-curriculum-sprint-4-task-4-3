# Coldline Task 4.3 — Output validation and audit

This repository starts from the Task 2 checkpoint, with the settled token verification in
`config/auth.yaml` and the settled access rule on `GET /api/v1/exceptions/{exception_id}`,
and adds a guardrail boundary, an audit sink, and two supplied bad model responses. The
guardrail in `src/worker/guardrail.py` checks a model answer against the strict output
schema in `schemas/exception-summary.schema.json`; `docs/security/output-policy.md` defines
what the system stores and shows when an answer fails that check. The audit sink in
`src/common/audit.py` writes audit events to PostgreSQL, and `docs/security/audit-events.md`
lists the events and the fields each one may carry. By default the model emulator returns a
valid answer; `poe scenario --response malformed` and `--response manipulated` make it return
a malformed answer or a manipulated one instead. At this checkpoint the worker stores whatever
the provider returns and records no audit event. You route every answer through the
guardrail, store the fail-safe outcome for a rejected one, record the audit events, and prove
it with deterministic negative tests.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tripleten-com/ai-system-engineering-curriculum-sprint-4-task-4-3/tree/main)

## Start the system

Prerequisites are Python 3.12 and Docker with Compose v2. The supplied bootstrap supports macOS
arm64/x86-64, Windows x86-64, and Linux x86-64/aarch64, and installs pinned uv 0.11.8 under
`.tools/bin`. If your computer cannot run the stack locally, use the Codespaces button above.

On macOS and most Linux distributions the interpreter is `python3`; substitute it wherever these
commands say `python`.

```shell
python infra/scripts/bootstrap.py
./.tools/bin/uv sync --frozen
./.tools/bin/uv run --frozen poe preflight
./.tools/bin/uv run --frozen poe start
./.tools/bin/uv run --frozen poe ready
./.tools/bin/uv run --frozen poe ingest
```

PowerShell and POSIX wrappers are available under `infra/scripts/`. After uv is on `PATH`, the
shorter `uv run --frozen poe <task>` form works; in PowerShell on Windows the pinned binary is
`.tools/bin/uv.exe`.

| Service | Local URL | Purpose |
|---|---|---|
| API | `http://localhost:8000` | Submit readings, poll exception summaries, search procedures |
| Token issuer: discovery document | `http://localhost:8180/.well-known/openid-configuration` | The development issuer's OIDC discovery document: its `issuer` and `jwks_uri` |
| Token issuer: key set | `http://localhost:8180/.well-known/jwks.json` | The published key set (JWKS) the settled `config/auth.yaml` names |
| Jaeger | `http://localhost:16686` | Open traces; the trace ids the audit records carry are these |
| Grafana | `http://localhost:3000` | Use the focused diagnostics dashboard |
| Prometheus | `http://localhost:9090` | Query bounded metrics and inspect the deployed alert rule |
| Alertmanager | `http://localhost:9093` | Inspect firing and resolved alerts |
| LocalStack S3/SQS | `http://localhost:4566` | Inspect the emulated object-storage and queue endpoint |

Each of these ports can be overridden by setting the matching `COLDLINE_API_HOST_PORT`,
`COLDLINE_ISSUER_HOST_PORT`, `COLDLINE_JAEGER_HOST_PORT`, `COLDLINE_GRAFANA_HOST_PORT`,
`COLDLINE_PROMETHEUS_HOST_PORT`, `COLDLINE_ALERTMANAGER_HOST_PORT`, or
`COLDLINE_LOCALSTACK_HOST_PORT` environment variable in your shell environment or a local
`.env` file (copy `.env.example`) if a default collides with something already running on your
machine. Keep the override in place for every `poe` command. If you remap the issuer port,
keep `config/auth.yaml` unchanged: it is supplied in this Task and names the default port.
Host-side tools (the in-process test harness and `poe token-check`) resolve the issuer's
origin from `COLDLINE_ISSUER_HOST_PORT` (the environment, then `.env`, then the default), and
the API uses the Compose-network origin.

This Task runs as its own Compose project, `coldline-task-4-3`. If an earlier Task's stack is
still running, run `poe stop` in that Task's repository first; otherwise `poe start` here fails
because the published ports are already taken.

PostgreSQL, Redis, worker metrics, and OTLP remain inside the Compose network. Codespaces uses the
same `compose.yaml` and keeps every forwarded port private. Redis keeps running only for an
earlier checkpoint's own contract test; no composition root reads it anymore.

### After you edit a file

The API image carries `src/api/routes.py` and the worker image carries
`src/worker/use_cases.py` as they were when they were built. After editing either, run
`poe start` again: it rebuilds both images and recreates the containers, which is what the Task
page means by "restart the stack as `README.md` describes". `poe restart` restarts the
existing containers **without rebuilding** and is not enough. Your tests under `tests/student/`
run the worker and the API in-process from your checkout and need no rebuild, only the running
issuer for the audit tests.

## Command path

For this Task, run the supplied commands in this order:

```text
poe start
poe ingest
poe scenario --response manipulated      # before any code change: keep this record
poe scenario                             # after Step 1
poe scenario --response malformed        # after Step 2
poe scenario --response manipulated      # after Step 2, and again after Step 3
poe audit-trail <exception_id>
poe student-tests
poe guardrail-mutation
poe verify
```

The exact public command is `./.tools/bin/uv run --frozen poe verify`, run from the repository
root. Where a Task page shortens a command to `poe <task>`, that is the form it means.

| Command | Use |
|---|---|
| `poe scenario [--response valid\|malformed\|manipulated]` | Send the supplied reading with a fresh identity and the chosen emulator response, wait for a finished state, and print the exception id, the state, and the trace ids. `valid` is the default. Its one read of the finished record, as `dispatcher-valid`, is a summary read in the audit trail |
| `poe audit-trail <exception_id>` | Print every audit record of one exception, oldest first, with its event, the exception id, the trace id of the request that recorded it, the time, and its fields. Runs inside the API container |
| `poe student-guard` | Read `tests/student/test_output_guardrail.py` and `tests/student/test_audit.py` without running them and apply five flat rules: only `import pytest`, the `annotations` future, the permitted `typing` names (`Any`, `Annotated`, `Literal`, `Optional`, `Union`, `cast`, `TYPE_CHECKING`, `Final`), and `InteractionHarness` may be imported; none of the listed environment names (`__file__`, `sys`, `importlib`, `getattr`, `open`, `Path`, any dunder, ...) appears anywhere, and neither `.format` nor `.format_map` is taken from anything (a format field traverses attributes inside a string; f-strings stay permitted); `pytest` is used only for fixtures, marks, `param` and `raises`; no function has a parameter named after a pytest built-in fixture (`request`, `monkeypatch`, `tmp_path`, ...: rename it, for example to `resp`); and every guardrail test asserts the `.state` of a record from `harness.run_worker(...)` while every audit test asserts over `harness.audit_trail(...)` or `harness.audit_text(...)`. Runs inside `poe verify` before anything executes either file and as the first step of `poe student-tests`; the assessed checks refuse to run a file it rejects |
| `poe integrity-record`, `poe integrity-check` | The first and last steps of `poe verify`: hash your four files and the checks' own files into a snapshot outside the repository, then compare the tree with it, so a file that changed while the run was in progress is named |
| `poe student-tests` | Run the student-test guard, then the supplied tests under `tests/student/`, including your two files and Task 2's settled access tests; a file the guard rejects is named and never collected. `poe student-tests-run` is the bare pytest run behind it and forwards arguments (`poe student-tests-run -k <name>`), as `poe e2e-tests` does for `poe e2e` |
| `poe guardrail-mutation` | Run your two files once as written, recording which response each guardrail test ran the worker with and which exception each audit test read, then rerun them against copies of `src/` with one thing changed each (the guardrail call bypassed so the raw answer goes straight to `COMPLETED`; the request headers added to the summary-read event) and report which of your tests still pass |
| `poe guardrail-binding` | Read `src/worker/use_cases.py` and `src/api/routes.py` without running them and check that the worker imports `validate_summary` from `worker.guardrail` once, at module level, rebinds neither the name nor the module, and uses the name only to call it, and that neither file imports the test runner's or the interpreter's modules (`pytest`, `_pytest`, `sys`, `importlib`, `builtins`, `gc`, `inspect`, `ctypes`, `types`, `runpy`), uses `exec`, `eval`, `compile`, `__import__`, `globals`, `setattr` or `delattr`, or reaches a dunder attribute. This is the static half of one assessed check about your code; its other half, run only when this passes, runs the worker in-process with no stack and checks that every answer reaches `validate_summary` exactly as the provider returned it and that the stored outcome follows the guardrail's verdict |
| `poe output-contract` | The assessed checks that read the running stack: the stored record of each supplied response, the audit trail's order, fields, values and trace ids, the absence of credentials, when a read is a summary read, and the inherited Task 2 access rule. Runs the module through `tests/security/assessed_run.py`, which requires every registered check to have executed and passed |
| `poe negative-tests-contract` | The assessed checks about your code and tests: the guard, the worker's guardrail binding (static over both application files, then the worker observed in-process: each answer handed to `validate_summary` as is, the stored outcome following its verdict), what each test ran, and the two mutations (only an assertion failure counts as a detection), through the same runner |
| `poe token-check <fixture>`, `poe auth-checks`, `poe auth-config` | Task 2's diagnosis tools over the settled `config/auth.yaml` and the access rule, kept |
| `poe answers` | The answer sheet's format only: `submission.yaml` records `answers: {}` |
| `poe submission` | The same check plus the permitted-files boundary: the diff from your merge base touches only the four permitted files |
| `poe verify` | The public student verification path: it starts the stack, exercises the inherited platform, and runs this Task's own checks |
| `poe queue-contract`, `poe slo-contract`, `poe gate-contract`, `poe runbook-contract` | Project 3's own checks, inherited and passing as shipped; `poe verify` runs them |
| `poe contract` | Check interfaces, boundaries, submissions, and repository structure |
| `poe smoke` | Check the initialized running platform, including the issuer's documents |
| `poe e2e` | Run the external API-to-worker workflow, including the joined trace |
| `poe migrate`, `poe migrate-down`, `poe migrate-current` | Step the schema by hand; the initializer brings it to head on every start |
| `poe restart` | Restart the existing API and worker containers **without rebuilding** |
| `poe stop` | Remove containers and the network, keeping named volumes |
| `poe reset` | Remove containers, the network, and local named volumes |

`poe verify` records an integrity snapshot of your four files and the checks' own files, runs
the student-test guard before anything executes either of your test files, then the unit
tests; it starts the stack, ingests the supplied corpus, runs the smoke tests, then this Task's
assessed checks against the running stack (one reading per supplied response, read back
through the database: `COMPLETED` with only the schema fields for the valid answer,
`NEEDS_REVIEW` with the fixed message, a reason code and none of the model's text for the two
bad answers; one read of each finished record and the audit trail's order, exception ids,
permitted fields and their values, and the exact trace ids of the submitting and reading
requests; no credential in any record; a summary read only for a read that returned a stored
outcome, for every state; the inherited access rule per token fixture and without a token),
then the end-to-end exception workflow, the inherited queue, SLO, gate, and runbook checks,
the answer-sheet format check, the assessed checks about your code and tests (the guard, the
worker's guardrail binding, what each test ran, and the two mutations), your student tests
(behind the guard again), the permitted-files boundary, and finally the integrity check
against the snapshot. Each assessed step requires every one of its registered checks to have
executed and passed. The Project 3
exercise commands (`poe inject-failure`, `poe redrive`, `poe trigger-alert-load`,
`poe verify-alert-recovery`, `poe dev-failure-lab`) still run but are not part of this Task.

## Folder map

```text
repository root/
├── config/              Retrieval configuration, settled since Sprint 2, and the settled auth.yaml
├── docs/                Student guidance, public contracts, fidelity notes, and the security material
│   ├── contracts/       Machine-readable public contracts, including this Task's (empty) answer schema
│   ├── fidelity/        Local-runtime boundary notes for each active adapter, including the emulator's responses
│   ├── security/        The supplied workflow, threat catalog, control matrix, access policy, output policy, and audit events
│   ├── architecture/    Supplied vector engine technical profiles, in prose
│   ├── retrieval/       Supplied retrieval pipeline reference
│   └── student/         This Task's contract, the settled threat model, and the supplied Project 3 runbook
├── infra/               Local setup and runtime configuration
│   ├── containers/      The API and worker Dockerfiles, with the build identity arguments
│   ├── issuer/          The development token issuer: its server script and the published key set
│   ├── observability/   Prometheus, Alertmanager, and Grafana configuration
│   ├── release/         The supplied release manifest, unchanged
│   ├── corpus/          Supplied synthetic corpus (one procedure carries the planted instruction), query set, and investigation
│   ├── judge/           Supplied cached judge evidence and its provenance record
│   ├── profiles/        Supplied engine and emulator profiles, and their provenance record
│   └── postgres/        Database initialization and the migration baseline stamp
├── loadtest/            Supplied traffic profile and provider-latency harness
├── migrations/          Alembic environment, revision template, and revisions, including the output fields and the audit table
├── schemas/             The supplied output schema the guardrail enforces
├── src/
│   ├── api/             HTTP application code, the retrieval and document paths, composition, the audit-trail command
│   │   └── security/    The settled TokenVerifier and require_access rule; not student-editable
│   ├── worker/          Background application code, the procedure lookup, the supplied guardrail, the dead-letter depth poller
│   ├── common/          The supplied audit sink both services use; not student-editable
│   ├── domain/          Shared domain code, contracts, the failure taxonomy, service and repository contracts
│   ├── ports/           Application interfaces
│   └── adapters/        Technology-specific implementations, including the model emulator and its responses, the audit store, the SQS adapter
└── tests/
    ├── unit/            Isolated behavior checks, including the guardrail's, the sink's, and the mutation tooling's
    ├── benchmark/       Supplied evaluation harness, metrics, and adoption policy
    ├── contract/        Interface, retrieval, and repository checks, and this Task's assessed output, audit, and negative-test checks
    ├── diagnostics/     Supplied stage inspector
    ├── doubles/         Supplied deterministic test doubles
    ├── failure/         Supplied Project 3 failure-lab and exercise scripts; not this Task's work
    ├── fixtures/        Supplied fixtures: the token fixtures and the credential values the audit checks search for
    ├── security/        Supplied tooling: the in-process harnesses, the student guard, the mutations, the trail reader
    ├── student/         Your test_output_guardrail.py and test_audit.py beside the settled access tests
    ├── smoke/           Running-platform checks
    └── e2e/             Supplied workflow tools and checks, including `poe scenario`
```

## Overview

Use the Task 3 lesson (Task 4.3 in this repository) to decide what to do. This README covers
local setup and repository orientation.

1. `README.md` — local setup, commands, and permitted changes.
2. [`docs/student/task-4-3-contract.md`](docs/student/task-4-3-contract.md) — what this Task
   assesses and who assesses it, the Check-list rows and the checks that read them, and the
   four permitted paths.
3. [`docs/security/output-policy.md`](docs/security/output-policy.md) — the schema, the accepted
   outcome, the fail-safe outcome with the fixed message, and the reason codes.
4. [`docs/security/audit-events.md`](docs/security/audit-events.md) — the events one interaction
   leaves, in order, and the fields each may carry.
5. [`src/worker/guardrail.py`](src/worker/guardrail.py) and
   [`src/common/audit.py`](src/common/audit.py) — the supplied guardrail and audit sink, with
   the call forms in their docstrings.
6. [`tests/student/test_output_guardrail.py`](tests/student/test_output_guardrail.py) and
   [`tests/student/test_audit.py`](tests/student/test_audit.py) — the templates you complete,
   with the harness documented in their docstrings.
7. [`docs/student/threat-model.md`](docs/student/threat-model.md) — the settled Task 1 threat
   model this Project's controls answer; TH-03 and TH-06 are the threats this Task closes with
   C-02 and C-03.

The application source lives in six flat packages:

| Package | Responsibility |
|---|---|
| `api` | HTTP delivery, API use cases, the retrieval workflow, versioned routes, token verification and the access rule, configuration, composition, and the audit-trail command |
| `worker` | Background processing, retries, procedure lookup, the output guardrail, the dead-letter depth poller, configuration, and composition |
| `common` | The audit sink the API and the worker share, and the event names |
| `domain` | Provider-neutral contracts, state rules, identity, redaction, embedding, chunking, fusion, access constraints, failure classification, service and repository contracts |
| `ports` | Exactly five visible application interfaces |
| `adapters` | PostgreSQL (exception records and audit records), pgvector retrieval, LocalStack SQS/DLQ, S3-compatible object storage, the deterministic model emulator and its supplied responses, the resilient model-provider wrapper, logs, traces |

`src/api/bootstrap.py` and `src/worker/bootstrap.py` compose each process from its settings and
adapters. Process settings live in `src/api/config.py` and `src/worker/config.py`; the token
verification settings live in `config/auth.yaml`.

## The five ports

Find the available interfaces in `src/ports/`. A port describes an application capability; an
adapter provides it using a concrete technology.

| Port | General responsibility |
|---|---|
| `ModelProvider` | Call an AI model service; it returns the provider's raw answer text, which the guardrail checks |
| `Retriever` | Look up relevant context or documents; the worker calls it too |
| `ObjectStore` | Store large binary objects or files |
| `JobQueue` | Publish and consume background work |
| `SecretProvider` | Read API keys and credentials; no adapter is composed yet |

## Test levels

| Level | Requires Compose | Main question |
|---|---:|---|
| Unit | No | Does one responsibility behave correctly, including failures? |
| Contract | Some | Do interfaces, schemas, paths, and dependency rules stay compatible? |
| Smoke | Yes | Did the complete local platform initialize and become observable? |
| E2E | Yes | Can an external client complete the supplied workflow, in one trace? |
| Student | Issuer | Does the worker fail safely on each bad answer, and does one interaction leave a complete trail without credentials? |

Contract checks marked `runtime` need the running stack. `poe contract` skips them; `poe verify`,
`poe runtime-contract`, `poe queue-contract`, `poe slo-contract`, and `poe gate-contract` run them.
Contract checks marked `assessed` read your four files, the running stack and the audit table,
and are expected to fail on a fresh checkout; `poe contract` skips them too, and
`poe output-contract`, `poe negative-tests-contract` and `poe verify` run them. Your guardrail
tests run the worker in-process from `src/` and need no stack; your audit tests also read the
in-process API with the `dispatcher-valid` token, whose verifier fetches the key set from the
configured `jwks_url`, so they need the issuer running.

## Submission checks

Run `poe verify` locally before opening your student pull request. Public GitHub CI repeats
the student checks, running `poe answers` first so a malformed sheet fails fast. This Task
records `answers: {}` and has no protected answer check: your code, your tests, and the audit
trail are the evidence, and `poe verify` is the whole automated assessment. Follow the Task
lesson's instructor-review and progression policy.

## Task boundary

Task 4.3 asks you to route the provider's answer through the supplied guardrail and store the
output policy's outcomes and the worker's audit events in `src/worker/use_cases.py`, record
the summary-read audit event in `src/api/routes.py`, write the three tests in
`tests/student/test_output_guardrail.py` and the two in `tests/student/test_audit.py`, run
`poe verify`, open a pull request that changes only those four files, and add the stored
records and the `poe audit-trail` output the Task page lists to the pull request description,
with each command and when you ran it.

The only student-editable paths are:

- `src/worker/use_cases.py`
- `src/api/routes.py`
- `tests/student/test_output_guardrail.py`
- `tests/student/test_audit.py`

Keep the schema (`schemas/`), the guardrail (`src/worker/guardrail.py`), the output policy and
the event list (`docs/security/`), the audit sink (`src/common/`) and its store, the emulator
and its supplied responses (`src/adapters/model/`), the corpus (`infra/corpus/`), the settled
Task 2 material (`config/auth.yaml`, `src/api/security/`, the token fixtures, the access
tests), the credential values under `tests/fixtures/credentials/`, the supplied tests, and
`.github/workflows/task.yml` exactly as supplied; the public check compares the diff from your
merge base against the four permitted files and reports any other change as a boundary
violation. In `src/api/routes.py`, the Task 2 access rule on `get_exception` stays as it is;
your change is the summary-read event inside that route.

### Student walkthrough

See **Task 3: Output validation and audit** in your course platform for the full walkthrough.
In outline: start the stack, run the manipulated response before changing any code and keep
that record, route the answer through `validate_summary` and store the validated fields, store
the fail-safe outcome for a rejected answer, run both bad responses, record the four worker
events and the summary-read event, reconstruct one interaction with `poe audit-trail`, write
the five tests, prove they can fail with `poe guardrail-mutation`, run `poe verify`, open and
merge your pull request, and submit on the platform.

## Operational limits

This local system does not authenticate users against a managed identity provider, terminate
TLS, or manage production secrets. The token issuer is a development service: it publishes one
fixed key set over plain HTTP and issues no tokens; the eight fixtures were signed once and
committed. The Compose PostgreSQL password,
the LocalStack access keys, and the worker's model-provider key are development values. These
values are listed once more in `tests/fixtures/credentials/test-values.yaml` so the audit
checks can search for them. Never place real credentials, personal data, or production records in this
repository. The handling note in the supplied scenario is synthetic; test with the supplied
readings only. The audit table stores the stored summary, which repeats the handling note;
Task 4 adds redaction.

The model emulator's three responses are a property of this emulator and of nothing else: the
guardrail bounds what any answer can store, and nothing here claims to detect or prevent
prompt injection. See [ModelProvider fidelity](docs/fidelity/ModelProvider.md).

Alertmanager here is configured with a "default" receiver that has no notification integration:
alerts are queryable through its own API but never sent anywhere real. Never add a webhook, email,
Slack, or paid integration; Sprints 1-4 are emulator-only and never call a hosted endpoint.

LocalStack's SQS emulation is a local reliability primitive, not a managed-service durability,
IAM, availability, or cost claim. Stopping and starting one Compose container is a local fault
control, not an ECS service event. See [JobQueue fidelity](docs/fidelity/JobQueue.md) for the
exact boundary.

Named volumes preserve local PostgreSQL, Redis, Prometheus, Alertmanager, Grafana, and Jaeger state
across `poe stop`; the audit table is in the PostgreSQL volume. LocalStack object and queue
contents are deliberately not persisted; the initializer re-uploads the supplied corpus
artifacts and re-provisions the queue on every start. The `poe reset` command deletes the named
volumes. This topology makes no backup, replication, high-availability, disaster-recovery,
capacity, latency-SLO, or availability claim beyond what Project 3 settled.

See [TokenIssuer fidelity](docs/fidelity/TokenIssuer.md),
[JobQueue fidelity](docs/fidelity/JobQueue.md),
[ModelProvider fidelity](docs/fidelity/ModelProvider.md),
[ObjectStore fidelity](docs/fidelity/ObjectStore.md), and
[Retriever fidelity](docs/fidelity/Retriever.md) for the active adapter boundaries. The
[local runtime evidence](docs/fidelity/local-runtime.md) records the current measurement and its
qualification limits.
