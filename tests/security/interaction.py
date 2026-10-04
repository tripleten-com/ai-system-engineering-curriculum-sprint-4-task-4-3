"""Coldline.

===================

File:              tests/security/interaction.py
Component:         Security tooling — In-process interaction harness
Purpose:           Run one exception through the worker, with a named emulator response, in
                    this process, and read the record and its audit trail back.
Interacts With:    src/worker/use_cases.py, src/worker/guardrail.py, src/common/audit.py,
                    src/adapters/model/deterministic.py, src/api/routes.py,
                    infra/corpus/documents.jsonl, tests/fixtures/credentials/test-values.yaml,
                    tests/security/harness.py, tests/security/trace.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Deterministic negative tests, in-process worker, mutation-checkable use
                    cases, audit trail as evidence
Tools:             Python 3.12, httpx, OpenTelemetry

The student's guardrail and audit tests run the worker here rather than through the running
stack, for the same reason the access tests do: ``poe verify`` reruns them against mutated
copies of ``src/worker/use_cases.py`` and ``src/api/routes.py``, and only code run in this
process can be pointed at such a copy. The worker application, the guardrail, the audit
sink, and the model emulator are the real ones; the exception store is the harness's memory
store, the procedure source returns the supplied planted procedure the running stack
retrieves for the scenario's reading, and the audit store is in memory. The emulator runs
with no latency, so a run takes milliseconds.

``InteractionHarness`` extends ``AccessHarness`` (the in-process API and the token fixtures)
with:

- ``await run_worker(response)``: create one queued exception for the scenario's reading,
  process it once with the named emulator response (``valid``, ``malformed``,
  ``manipulated``), and return the stored record;
- ``audit_trail(exception_id)``: the audit records of one exception, oldest first;
- ``audit_text(exception_id)``: the same records rendered as text, one JSON line each,
  for a test that asserts what the trail must not contain;
- ``secret_values()``: the supplied credential values the credential-absence test must
  not find in any record;
- ``review_message``, ``reason_codes``, ``responses``: the output policy's fixed message,
  the guardrail's codes, and the response names, so a test can assert them without
  importing the modules that define them.

When the assessed checks run a student file, each worker run and each request is recorded
against the pytest case that made it (``tests/security/trace.py``).

Three module-level helpers serve the assessed rows and are not harness methods, so a
student file (which may import ``InteractionHarness`` alone) cannot reach them:
``replayed_answer`` runs the real emulator over the request the worker sends for one
reading, so the live rows know the raw answer text, its digest and its length without
trusting any record; ``place_record`` puts a record of any state and summary into a
harness's store, so the read-eligibility row can read every state; ``run_application``
is what ``run_worker`` runs, with the worker class and the provider as parameters, so the
trusted observation (``tests/security/guardrail_observation.py``) can run the student's
worker with the provider's answers captured and the guardrail stood in for.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

import yaml
from opentelemetry import trace as otel_trace
from opentelemetry.sdk.trace import TracerProvider

from adapters.model.deterministic import RESPONSES, DeterministicModelProvider
from api.security.tokens import TokenVerifier
from common.audit import AuditRecord
from domain.chunking import chunk_document
from domain.contracts import (
    AccessLabel,
    Candidate,
    DocumentRecord,
    ExceptionJob,
    ExceptionRecord,
    ExceptionState,
    ModelAnswer,
    ModelRequest,
    SensorReading,
)
from ports import ModelProvider
from tests.security import trace
from tests.security.harness import TASK_ROOT, AccessHarness
from worker.config import WorkerSettings
from worker.guardrail import REASON_CODES, REVIEW_MESSAGE
from worker.procedures import EXCERPT_WORDS, ProcedureExcerpt, excerpt_from
from worker.use_cases import WorkerApplication

BASELINE_PATH = Path("tests/e2e/baseline-exception.json")
CORPUS_PATH = Path("infra/corpus/documents.jsonl")
CREDENTIALS_PATH = Path("tests/fixtures/credentials/test-values.yaml")
# The supplied procedure the running stack retrieves for the scenario's reading (an upper
# excursion in the procedure tenancy), and the one that carries the planted instruction.
PLANTED_DOCUMENT_ID = "playbook-thermal-excursion"
NOW = datetime(2026, 9, 1, tzinfo=UTC)
_TRACER = otel_trace.get_tracer(__name__)


def planted_excerpt(root: Path = TASK_ROOT) -> ProcedureExcerpt:
    """Return the excerpt the worker sends for the scenario's reading: the planted procedure.

    The supplied corpus is read as the ingestion reads it and chunked as the data layer
    chunks it, and the first chunk is bounded as ``ProcedureLookup`` bounds the top-ranked
    candidate, so the excerpt here is the one the running worker sends.
    """
    for line in (root / CORPUS_PATH).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        document = DocumentRecord.model_validate(json.loads(line))
        if document.document_id != PLANTED_DOCUMENT_ID:
            continue
        first = chunk_document(document)[0]
        return excerpt_from(
            (
                Candidate(
                    chunk_id=first.chunk_id,
                    document_id=first.document_id,
                    rank=1,
                    score=1.0,
                    text=first.text,
                    access=AccessLabel(
                        tenant_id=first.access.tenant_id, access_tier=first.access.access_tier
                    ),
                    provenance_revision=first.provenance.revision,
                ),
            ),
            words=EXCERPT_WORDS,
        )
    raise ValueError(f"{CORPUS_PATH.as_posix()} holds no document {PLANTED_DOCUMENT_ID!r}")


def secret_values(root: Path = TASK_ROOT) -> tuple[str, ...]:
    """Return the supplied credential values, in file order."""
    document = yaml.safe_load((root / CREDENTIALS_PATH).read_text(encoding="utf-8"))
    values = document.get("values") if isinstance(document, dict) else None
    if not isinstance(values, dict) or not all(
        isinstance(name, str) and isinstance(value, str) and value for name, value in values.items()
    ):
        raise ValueError(f"{CREDENTIALS_PATH.as_posix()} must map names to values under `values:`")
    return tuple(values.values())


def scenario_reading(root: Path = TASK_ROOT, *, response: str) -> SensorReading:
    """Return the scenario's reading with a fresh identity and the named response selector."""
    fixture = json.loads((root / BASELINE_PATH).read_text(encoding="utf-8"))
    reading = dict(cast(dict[str, Any], fixture["reading"]))
    suffix = uuid4().hex[:12]
    reading["reading_id"] = f"reading-harness-{suffix}"
    reading["shipment_id"] = f"shipment-harness-{suffix}"
    reading["recorded_at"] = NOW.isoformat()
    reading["emulator_response"] = response
    return SensorReading.model_validate(reading)


class WorkerLike(Protocol):
    """What ``run_application`` needs of a worker: ``process`` one delivery of one job."""

    async def process(self, job: ExceptionJob, *, delivery_count: int) -> object:
        """Process one delivery and return the disposition."""
        ...


class PlantedProcedures:
    """Return the planted procedure for every reading, as the running retrieval does."""

    def __init__(self, excerpt: ProcedureExcerpt) -> None:
        """Bind the source to the one excerpt it answers with."""
        self._excerpt = excerpt
        self.readings: list[SensorReading] = []

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Record the reading and answer with the planted excerpt."""
        self.readings.append(reading)
        return self._excerpt


def _ensure_tracer_provider() -> None:
    """Install an SDK tracer provider once, so spans here carry real trace ids.

    Without a provider every span is non-recording and has no trace id; with one, the
    worker run and each in-process request get a trace id of their own, as they do in the
    running stack. A provider another module installed first is kept.
    """
    if isinstance(otel_trace.get_tracer_provider(), otel_trace.ProxyTracerProvider):
        otel_trace.set_tracer_provider(TracerProvider())


class InteractionHarness(AccessHarness):
    """One in-process worker and API over one memory store and one memory audit sink."""

    responses: tuple[str, ...] = RESPONSES
    review_message: str = REVIEW_MESSAGE
    reason_codes: tuple[str, ...] = REASON_CODES

    def __init__(
        self,
        root: Path = TASK_ROOT,
        *,
        token_verifier: TokenVerifier | None = None,
        trace_path: Path | None = None,
    ) -> None:
        """Build the API as ``AccessHarness`` does, and the worker's collaborators beside it."""
        _ensure_tracer_provider()
        super().__init__(root, token_verifier=token_verifier, trace_path=trace_path)
        self._planted = planted_excerpt(root)
        self._emulator = DeterministicModelProvider(
            latency_ms=0, provider_key=WorkerSettings.model_fields["model_provider_key"].default
        )

    async def run_worker(self, response: str = "valid") -> ExceptionRecord:
        """Process one fresh exception once, with the named emulator response, and return it.

        The reading is the scenario's, with a fresh identity each call; the record starts
        ``QUEUED`` as the API leaves it, the worker's ``process`` runs once as the queue
        would run it (delivery count 1) inside a processing span of its own, and the record
        as the worker left it is returned. Every audit event the worker recorded is in
        ``audit_trail(record.exception_id)``.
        """
        return await run_application(self, response)

    def queued_exception(self) -> str:
        """Create one exception that is still ``QUEUED``, with no outcome, and return its id."""
        reading = scenario_reading(self.root, response="valid")
        exception_id = f"exc-{uuid4().hex}"
        self.repository.records[exception_id] = ExceptionRecord(
            exception_id=exception_id,
            reading=reading,
            state=ExceptionState.QUEUED,
            accepted_at=NOW,
            updated_at=NOW,
        )
        return exception_id

    def audit_trail(self, exception_id: str) -> list[AuditRecord]:
        """Return the audit records of one exception, oldest first."""
        return self._audit_store.trail_now(exception_id)

    def audit_text(self, exception_id: str) -> str:
        """Return the audit records of one exception as text, one JSON line per record.

        Every field and value of every record is in this text, so a test can assert that
        a token, a header name, or a secret value is nowhere in the trail.
        """
        return "\n".join(record.rendered() for record in self.audit_trail(exception_id))

    def secret_values(self) -> tuple[str, ...]:
        """Return the supplied credential values no audit record may contain."""
        return secret_values(self.root)


def rendered_trail(records: Sequence[AuditRecord]) -> str:
    """Render records as the harness renders them, for checks that hold a list already."""
    return "\n".join(record.rendered() for record in records)


async def run_application(
    harness: InteractionHarness,
    response: str,
    *,
    application_class: Callable[..., WorkerLike] = WorkerApplication,
    provider: ModelProvider | None = None,
) -> ExceptionRecord:
    """Process one fresh exception once through a worker built on the harness's collaborators.

    This is ``harness.run_worker(response)``: a fresh ``QUEUED`` record for the scenario's
    reading, a worker over the harness's store, emulator (or the ``provider`` given, which
    the trusted observation uses to capture the answers), planted procedure and audit
    sink, one ``process`` call as the queue would make it (delivery count 1) inside a
    processing span, and the record as the worker left it. ``application_class`` is the
    student's ``WorkerApplication`` unless the observation passes the one it loaded.
    """
    if response not in RESPONSES:
        choices = ", ".join(RESPONSES)
        raise ValueError(f"unknown response {response!r}; choose one of {choices}")
    reading = scenario_reading(harness.root, response=response)
    exception_id = f"exc-{uuid4().hex}"
    harness.repository.records[exception_id] = ExceptionRecord(
        exception_id=exception_id,
        reading=reading,
        state=ExceptionState.QUEUED,
        accepted_at=NOW,
        updated_at=NOW,
    )
    application = application_class(
        harness.repository,
        harness._emulator if provider is None else provider,
        PlantedProcedures(harness._planted),
        audit=harness._audit,
        clock=lambda: NOW,
    )
    job = ExceptionJob(exception_id=exception_id, reading=reading, accepted_at=NOW)
    with _TRACER.start_as_current_span(
        "coldline.process_exception",
        attributes={"coldline.exception_id": exception_id, "coldline.delivery_count": 1},
    ):
        disposition = await application.process(job, delivery_count=1)
    value = getattr(disposition, "value", disposition)
    trace.record(
        harness._trace,
        {
            "kind": "worker",
            "response": response,
            "exception_id": exception_id,
            "disposition": value if isinstance(value, str) else str(value),
        },
    )
    return harness.repository.records[exception_id]


def replayed_answer(
    *, exception_id: str, reading: SensorReading, root: Path = TASK_ROOT
) -> ModelAnswer:
    """Return the raw answer the real emulator gives the request the worker sends for a reading.

    The request is built as ``WorkerApplication.process`` builds it: the reading's fields,
    the planted procedure the running stack retrieves for the scenario's reading, and the
    reading's response selector. The emulator is deterministic, so this is the text the
    running worker received, and its digest and length are what the model-response event
    must carry. Nothing from any record or audit row is trusted on the way.
    """
    planted = planted_excerpt(root)
    provider = DeterministicModelProvider(
        latency_ms=0, provider_key=WorkerSettings.model_fields["model_provider_key"].default
    )
    request = ModelRequest(
        exception_id=exception_id,
        shipment_id=reading.shipment_id,
        temperature_c=reading.temperature_c,
        allowed_min_c=reading.allowed_min_c,
        allowed_max_c=reading.allowed_max_c,
        handling_note=reading.handling_note,
        procedure_id=planted.document_id,
        procedure_excerpt=planted.text,
        emulator_response=reading.emulator_response,
    )
    return asyncio.run(provider.summarize(request))


def place_record(
    harness: InteractionHarness,
    state: ExceptionState,
    *,
    summary: str | None,
    rejection_reason: str | None = None,
) -> str:
    """Put one record of the given state and summary into the harness's store; return its id.

    For the read-eligibility row: a record in any of the six states, with or without a
    stored summary, exactly as the database could hold it, so the route's decision to
    record a summary read can be judged for every combination.
    """
    exception_id = f"exc-{uuid4().hex}"
    stored_outcome = summary is not None and state is ExceptionState.COMPLETED
    harness.repository.records[exception_id] = ExceptionRecord(
        exception_id=exception_id,
        reading=scenario_reading(harness.root, response="valid"),
        state=state,
        accepted_at=NOW,
        updated_at=NOW,
        summary=summary,
        handling_class="thermal_excursion" if stored_outcome else None,
        next_step="operational_review" if stored_outcome else None,
        rejection_reason=rejection_reason,
        failure_reason="model_provider_exhausted" if state is ExceptionState.FAILED else None,
    )
    return exception_id
