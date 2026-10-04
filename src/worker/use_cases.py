"""Coldline.

===================

File:              src/worker/use_cases.py
Component:         Worker — Use Cases
Purpose:           Coordinate one provider-neutral exception-processing attempt.
Interacts With:    LocalStack SQS, domain, ports, adapters, src/worker/guardrail.py,
                    src/common/audit.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Background processing, retries, idempotency, failure classification,
                    retrieval, output validation, audit events
Tools:             Python 3.12

For each job the worker logs the reading it took, retrieves the matching procedure
through the Retriever port, sends the reading, the handling note and the procedure
excerpt to the model provider, and stores what it finds in the provider's raw answer.

Task 4.3 edits this file, in ``WorkerApplication.process``: route the provider's raw
answer through ``validate_summary`` (``src/worker/guardrail.py``) before the transition
that stores it, store the fail-safe outcome of ``docs/security/output-policy.md`` on the
rejection path, and record the worker's four audit events of
``docs/security/audit-events.md`` through the audit sink this class is composed with.
At this checkpoint the worker still stores whatever ``parse_summary`` finds, and records
no audit event; the sink is wired in and unused.
"""

import json
import logging
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from common.audit import AuditRecorder
from domain.contracts import (
    ExceptionJob,
    ExceptionState,
    ModelAnswer,
    ModelRequest,
    ModelSummary,
    SensorReading,
)
from domain.errors import TerminalProviderError
from domain.failures import RetrievalUnavailable
from domain.repositories import ExceptionRepository
from ports import ModelProvider
from worker.procedures import ProcedureExcerpt

LOGGER = logging.getLogger(__name__)
# The finished states a repeated delivery replays without a new model call. From Task 4.3
# NEEDS_REVIEW is finished too: the answer came back and was refused, and a redelivery must
# not ask the provider again.
FINISHED_STATES: frozenset[ExceptionState] = frozenset(
    {ExceptionState.COMPLETED, ExceptionState.FAILED, ExceptionState.NEEDS_REVIEW}
)


class ProcessingDisposition(StrEnum):
    """Tell the transport loop whether to acknowledge or retry a delivery."""

    ACK = "ACK"
    ACK_EXISTING = "ACK_EXISTING"
    ACK_MISSING = "ACK_MISSING"
    RETRY = "RETRY"


class ProcedureSource(Protocol):
    """Find the procedure excerpt for one reading."""

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Return the excerpt, or an empty one when nothing matched."""
        ...


def parse_summary(answer: ModelAnswer) -> ModelSummary:
    """Read the summary out of the provider's raw answer with a plain parse.

    This is the opening checkpoint's reading of the answer, and what Task 4.3
    replaces: the summary is the ``summary`` field of the JSON document, and
    nothing checks the document's shape beyond finding that one string. An
    answer that is not JSON, or has no summary string, is stored as the text
    the provider returned.
    """
    try:
        payload = json.loads(answer.text)
    except json.JSONDecodeError:
        payload = None
    summary = payload.get("summary") if isinstance(payload, dict) else None
    return ModelSummary(
        summary=summary if isinstance(summary, str) else answer.text,
        provider=answer.provider,
    )


class WorkerApplication:
    """Apply bounded model processing to one durable exception job."""

    def __init__(
        self,
        repository: ExceptionRepository,
        provider: ModelProvider,
        procedures: ProcedureSource,
        *,
        audit: AuditRecorder,
        clock: Callable[[], datetime],
        maximum_attempts: int = 3,
    ) -> None:
        """Receive collaborators, the audit sink, and a positive delivery-attempt limit."""
        if maximum_attempts < 1:
            raise ValueError("maximum_attempts must be positive")
        self._repository = repository
        self._provider = provider
        self._procedures = procedures
        self._audit = audit
        self._clock = clock
        self._maximum_attempts = maximum_attempts

    async def process(self, job: ExceptionJob, *, delivery_count: int) -> ProcessingDisposition:
        """Process one delivery and tell the queue whether it can be acknowledged.

        Finished identities (completed, failed, or awaiting review) are safe
        replays and need no new model call. In-flight work is retried until the
        third delivery. A provider result is persisted before ``ACK`` is
        returned. A provider failure the provider itself classified as terminal
        fails immediately, on the first delivery, without spending a redelivery
        on an outcome that cannot change. Any other provider failure, and a
        retrieval backend that cannot answer, returns ``RETRY`` unless the
        delivery limit is exhausted. A missing record returns a distinct
        acknowledgement so the runtime can expose the broken
        persistence-before-publish invariant.
        """
        LOGGER.info(
            "reading job exception_id=%s shipment_id=%s handling_note=%s",
            job.exception_id,
            job.reading.shipment_id,
            job.reading.handling_note,
        )
        record = await self._repository.get(job.exception_id)
        if record is None:
            return ProcessingDisposition.ACK_MISSING
        if record.state in FINISHED_STATES:
            return ProcessingDisposition.ACK_EXISTING
        if record.state is ExceptionState.PROCESSING:
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="processing_attempts_exhausted",
                )
                return ProcessingDisposition.ACK
            return ProcessingDisposition.RETRY

        # PROCESSING is durable before the provider call starts. Recovery can
        # therefore distinguish work that never started from interrupted work.
        await self._repository.transition(
            job.exception_id,
            {ExceptionState.QUEUED},
            ExceptionState.PROCESSING,
        )

        # Task 4.3, Step 3: the first audit event, `processing_requested`, belongs here,
        # once the record is this attempt's: the reading id and the delivery count, and no
        # caller identity (the intake is unauthenticated). docs/security/audit-events.md
        # lists each event's fields; src/common/audit.py shows the call form.

        try:
            procedure = await self._procedures.find(job.reading)
        except RetrievalUnavailable:
            # The corpus store did not answer. That is this attempt failing,
            # not the provider, so it spends one processing attempt and is
            # otherwise retried like any interrupted attempt.
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="processing_attempts_exhausted",
                )
                return ProcessingDisposition.ACK
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.QUEUED,
            )
            return ProcessingDisposition.RETRY

        try:
            answer = await self._provider.summarize(
                ModelRequest(
                    exception_id=job.exception_id,
                    shipment_id=job.reading.shipment_id,
                    temperature_c=job.reading.temperature_c,
                    allowed_min_c=job.reading.allowed_min_c,
                    allowed_max_c=job.reading.allowed_max_c,
                    handling_note=job.reading.handling_note,
                    procedure_id=procedure.document_id,
                    procedure_excerpt=procedure.text,
                    emulator_response=job.reading.emulator_response,
                )
            )
        except TerminalProviderError:
            # The provider already decided a retry cannot succeed. Recording
            # the failure now, instead of after wasted redeliveries, is the
            # whole point of classifying it at the provider boundary.
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.FAILED,
                failure_reason="model_provider_terminal_failure",
            )
            return ProcessingDisposition.ACK
        except Exception:
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="model_provider_exhausted",
                )
                return ProcessingDisposition.ACK
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.QUEUED,
            )
            return ProcessingDisposition.RETRY

        # Task 4.3, Steps 1 to 3: the answer came back. Record `model_responded` (its digest
        # and length, never its text), pass `answer.text` to `validate_summary`, record the
        # validation result, and store only what came back from the guardrail: the validated
        # summary with its handling class and next step on the COMPLETED transition, or the
        # output policy's fixed message and the reason code on the NEEDS_REVIEW transition.
        # Record `outcome_stored` (the state and summary about to be stored) immediately
        # before that terminal transition, as docs/security/audit-events.md says: a read can
        # return the outcome only after the transition, so the event always precedes the
        # read in the trail. At this checkpoint the plain parse below stores whatever the
        # provider returned.
        summary = parse_summary(answer)
        # Terminal persistence happens before the transport loop acknowledges.
        await self._repository.transition(
            job.exception_id,
            {ExceptionState.PROCESSING},
            ExceptionState.COMPLETED,
            summary=summary.summary,
        )
        return ProcessingDisposition.ACK
