"""Coldline.

===================

File:              tests/unit/worker/test_config.py
Component:         Unit tests — Test Config
Purpose:           Unit tests for the worker configuration boundary.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Fast feedback, failure paths, state invariants
Tools:             Python 3.12, pytest, Redis, Pydantic
"""

import pytest
from pydantic import ValidationError

from worker.config import WorkerSettings


def _settings(monkeypatch: pytest.MonkeyPatch) -> WorkerSettings:
    """Build settings from the three required dependency addresses only."""
    monkeypatch.setenv("COLDLINE_DATABASE_URL", "postgresql://user:pass@postgres:5432/coldline")
    monkeypatch.setenv("COLDLINE_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("COLDLINE_OTEL_ENDPOINT", "http://jaeger:4317")
    monkeypatch.delenv("COLDLINE_MODEL_PROVIDER_KEY", raising=False)
    return WorkerSettings(_env_file=None)


def test_worker_settings_require_dependency_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker must not silently invent working dependency credentials."""
    monkeypatch.delenv("COLDLINE_DATABASE_URL", raising=False)
    monkeypatch.delenv("COLDLINE_REDIS_URL", raising=False)
    monkeypatch.delenv("COLDLINE_OTEL_ENDPOINT", raising=False)

    with pytest.raises(ValidationError):
        WorkerSettings(_env_file=None)


def test_worker_settings_keep_the_bounded_retry_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Compose values must retain three attempts and 30-second stale claiming."""
    settings = _settings(monkeypatch)

    assert settings.maximum_attempts == 3
    assert settings.stale_message_ms == 30_000
    assert settings.model_latency_ms == 250


def test_worker_settings_carry_the_provider_key_as_a_string_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """At this checkpoint the provider key is a literal in the settings module itself."""
    settings = _settings(monkeypatch)

    assert settings.model_provider_key == "coldline-dev-provider-key-v1"


def test_worker_settings_name_the_procedure_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Procedure retrieval runs under one fixed tenancy with a bounded candidate count."""
    settings = _settings(monkeypatch)

    assert settings.procedure_tenant == "tenant-northwind"
    assert 1 <= settings.procedure_top_k <= 12
