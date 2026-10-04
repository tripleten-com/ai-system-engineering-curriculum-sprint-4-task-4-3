"""Coldline.

===================

File:              src/worker/bootstrap.py
Component:         Worker — Bootstrap
Purpose:           Compose and run the SQS-backed Coldline worker.
Interacts With:    LocalStack SQS, PostgreSQL, domain, ports, adapters, the audit sink
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Background processing, idempotency, bounded resilience, redrive, retrieval,
                    audit
Tools:             Python 3.12, PostgreSQL, pgvector, boto3, OpenTelemetry, Prometheus
"""

import asyncio
import logging
import signal
from datetime import UTC, datetime

import asyncpg
from opentelemetry import trace
from prometheus_client import start_http_server

from adapters.logging import configure_json_logging
from adapters.model import DeterministicModelProvider, ResilientModelProvider
from adapters.persistence import PostgresAuditStore, PostgresExceptionRepository
from adapters.queue import SqsJobQueue, create_sqs_client
from adapters.retriever import PostgresHybridRetriever
from adapters.telemetry import configure_tracing
from common.audit import AuditSink
from domain.contracts import AccessTier, AuthorizationContext
from domain.tenant_authorization import TenantBoundaryAccessConstraints
from ports import Retriever
from worker.config import WorkerSettings
from worker.procedures import ProcedureLookup
from worker.queue_monitor import poll_dead_letter_depth
from worker.runtime import run_loop
from worker.use_cases import WorkerApplication


def compose_emulator(settings: WorkerSettings) -> DeterministicModelProvider:
    """Build the provider client the worker talks to, carrying the configured key."""
    return DeterministicModelProvider(
        latency_ms=settings.model_latency_ms,
        provider_key=settings.model_provider_key,
    )


def compose_model_provider(
    settings: WorkerSettings, emulator: DeterministicModelProvider
) -> ResilientModelProvider:
    """Wrap the provider client in the Task 3.2 timeout and attempt bounds."""
    return ResilientModelProvider(
        emulator,
        timeout_seconds=settings.model_timeout_ms / 1000,
        max_attempts=settings.model_provider_max_attempts,
        backoff_seconds=settings.model_retry_backoff_ms / 1000,
    )


def compose_procedures(retriever: Retriever, settings: WorkerSettings) -> ProcedureLookup:
    """Bind procedure retrieval to the worker's one fixed service scope.

    The worker is not a caller with its own tenancy. It reads the tenancy the
    laboratory's handling procedures live under, with the restricted
    clearance, because it has to find the matching procedure for any shipment
    whatever tier that procedure carries.
    """
    return ProcedureLookup(
        retriever,
        scope=AuthorizationContext(
            tenant_id=settings.procedure_tenant, clearance=AccessTier.RESTRICTED
        ),
        top_k=settings.procedure_top_k,
    )


def compose_audit(pool: asyncpg.Pool) -> AuditSink:
    """Build the audit sink over the PostgreSQL audit table, on the worker's own pool."""
    return AuditSink(PostgresAuditStore(pool))


async def run() -> None:
    """Compose the worker, run it, and release every owned resource.

    This is wiring only. Domain decisions stay in ``WorkerApplication`` and
    provider and transport behavior stay behind their ports. Signal handlers
    cancel both background tasks together, then the ``finally`` block closes
    PostgreSQL and the trace provider.
    """
    settings = WorkerSettings()  # type: ignore[call-arg]  # protected environment is the source
    configure_json_logging(settings.service_name)
    logging.getLogger(__name__).info("worker starting build_version=%s", settings.build_version)
    tracer_provider = configure_tracing(settings.service_name, settings.otel_endpoint)
    tracer = trace.get_tracer(__name__)
    pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=4)
    sqs_client = create_sqs_client(
        endpoint_url=settings.s3_endpoint,
        region_name=settings.s3_region,
        access_key_id=settings.s3_access_key_id,
        secret_access_key=settings.s3_secret_access_key,
    )
    queue_url = await asyncio.to_thread(
        lambda: sqs_client.get_queue_url(QueueName=settings.queue_name)["QueueUrl"]
    )
    # Task 3.4's own resolution, alongside the main queue's: the dead-letter
    # monitor polls this queue directly, never through JobQueue, since
    # SqsJobQueue is bound to the main queue only.
    dead_letter_queue_url = await asyncio.to_thread(
        lambda: sqs_client.get_queue_url(QueueName=settings.dead_letter_name)["QueueUrl"]
    )
    queue = SqsJobQueue(sqs_client, queue_url=queue_url)
    start_http_server(settings.metrics_port)
    provider = compose_model_provider(settings, compose_emulator(settings))
    # The worker reads the corpus through the same supplied hybrid adapter the
    # API uses, on its own pool, constrained to the procedure tenancy.
    retriever = PostgresHybridRetriever(pool, access_constraints=TenantBoundaryAccessConstraints())
    application = WorkerApplication(
        PostgresExceptionRepository(pool),
        provider,
        compose_procedures(retriever, settings),
        audit=compose_audit(pool),
        clock=lambda: datetime.now(UTC),
        maximum_attempts=settings.maximum_attempts,
    )
    worker_task = asyncio.create_task(
        run_loop(queue, application, tracer, stale_message_ms=settings.stale_message_ms)
    )
    monitor_task = asyncio.create_task(poll_dead_letter_depth(sqs_client, dead_letter_queue_url))

    def cancel_both() -> None:
        worker_task.cancel()
        monitor_task.cancel()

    loop = asyncio.get_running_loop()
    for shutdown_signal in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(shutdown_signal, cancel_both)
    try:
        await worker_task
    except asyncio.CancelledError:
        pass
    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass
        await pool.close()
        tracer_provider.shutdown()


if __name__ == "__main__":
    asyncio.run(run())
