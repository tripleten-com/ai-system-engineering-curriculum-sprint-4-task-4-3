"""Coldline.

===================

File:              src/worker/config.py
Component:         Worker — Config
Purpose:           Own and validate every worker environment read.
Interacts With:    LocalStack SQS, domain, ports, and adapters
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Background processing, bounded resilience, redrive, procedure retrieval
Tools:             Python 3.12, boto3, LocalStack, Pydantic
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    """Describe the protected runtime configuration for the worker service."""

    model_config = SettingsConfigDict(env_prefix="COLDLINE_", extra="forbid")

    database_url: str = Field(min_length=1)
    redis_url: str = Field(min_length=1)
    otel_endpoint: str = Field(min_length=1)
    service_name: str = "coldline-worker"
    # Vestigial: named the retired Redis Streams key and consumer group. Nothing
    # reads either field anymore; left at their original values rather than
    # renamed, since SQS naming rules never applied to a field nothing uses.
    stream_name: str = "coldline.exception.jobs"
    consumer_group: str = "coldline-workers"
    consumer_name: str = "worker-1"
    maximum_attempts: int = Field(default=3, ge=1, le=3)
    stale_message_ms: int = Field(default=30_000, ge=1_000)
    model_latency_ms: int = Field(default=250, ge=0, le=10_000)
    metrics_port: int = Field(default=9100, ge=1024, le=65535)
    # Task 3.1 release identity, baked into the image by the release manifest's build
    # argument and logged once at startup so a rollout is visible in the worker logs.
    build_version: str = Field(default="dev", min_length=1, max_length=64)
    # Task 3.2 provider-resilience bounds. These wrap every ModelProvider call
    # in its own timeout and attempt budget, independent of the transport's
    # own delivery-count-based redelivery above.
    model_timeout_ms: int = Field(default=2_000, ge=1, le=30_000)
    model_provider_max_attempts: int = Field(default=2, ge=1, le=5)
    model_retry_backoff_ms: int = Field(default=100, ge=0, le=10_000)
    # The model provider's key. The worker hands it to the provider client at
    # composition time, the way a hosted client would carry an API key. The
    # development emulator takes the key and checks nothing about it yet.
    model_provider_key: str = Field(default="coldline-dev-provider-key-v1", min_length=1)
    # Procedure retrieval. The worker looks the matching procedure up through
    # the Retriever port with one fixed service scope: the tenancy the
    # laboratory's handling procedures live under, and every tier of it.
    procedure_tenant: str = Field(
        default="tenant-northwind", min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"
    )
    procedure_top_k: int = Field(default=3, ge=1, le=12)
    # Task 3.3 queue identity. The worker resolves this name to a queue URL at
    # startup; the queue's own visibility timeout and dead-letter redrive policy
    # are provisioned once, by the initializer, and are not the worker's to set.
    # LocalStack serves every emulated service through one edge endpoint, so the
    # worker's queue client reuses the already-supplied S3 endpoint/credentials
    # below rather than a second, redundant set of environment variables. The
    # worker has no S3 use of its own; these exist here only for that endpoint.
    s3_endpoint: str = Field(default="http://localstack:4566", min_length=1)
    s3_region: str = Field(default="us-east-1", min_length=2)
    s3_access_key_id: str = Field(default="localstack-development-key", min_length=1)
    s3_secret_access_key: str = Field(default="localstack-development-secret", min_length=1)
    queue_name: str = Field(default="coldline-exception-jobs", min_length=1)
    # Task 3.4 dead-letter queue identity. The worker resolves this name to a
    # queue URL at startup, the same way it resolves `queue_name`, and polls its
    # depth for the `ColdlineDeadLetterQueueBacklog` alert
    # (`infra/observability/alerts.yml`, `src/worker/queue_monitor.py`). The name
    # matches the initializer's own provisioning and
    # `tests/failure/force_dlq_arrival.py`'s `DEAD_LETTER_NAME` constant.
    dead_letter_name: str = Field(default="coldline-exception-jobs-dlq", min_length=1)
