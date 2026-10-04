"""Coldline.

===================

File:              tests/unit/worker/test_bootstrap.py
Component:         Unit tests — Worker composition
Purpose:           Unit tests for the worker's provider and procedure composition.
Interacts With:    src/worker/bootstrap.py
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Composition root, configuration flows inward
Tools:             Python 3.12, pytest
"""

import pytest

from adapters.model import ResilientModelProvider
from domain.contracts import AccessTier
from tests.doubles import StubRetriever
from worker.bootstrap import compose_emulator, compose_model_provider, compose_procedures
from worker.config import WorkerSettings


def _settings(monkeypatch: pytest.MonkeyPatch, **overrides: str) -> WorkerSettings:
    """Build worker settings from the required addresses plus any override."""
    monkeypatch.setenv("COLDLINE_DATABASE_URL", "postgresql://user:pass@postgres:5432/coldline")
    monkeypatch.setenv("COLDLINE_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("COLDLINE_OTEL_ENDPOINT", "http://jaeger:4317")
    for name, value in overrides.items():
        monkeypatch.setenv(f"COLDLINE_{name}", value)
    return WorkerSettings(_env_file=None)


def test_worker_hands_its_configured_provider_key_to_the_emulator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The key the settings carry is the key the provider client is built with."""
    settings = _settings(monkeypatch, MODEL_PROVIDER_KEY="composition-check-key")

    emulator = compose_emulator(settings)

    assert emulator.provider_key == "composition-check-key"
    assert isinstance(compose_model_provider(settings, emulator), ResilientModelProvider)


def test_worker_composes_procedure_retrieval_under_the_configured_tenancy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Procedure lookups run under the settings' tenancy with the restricted clearance."""
    settings = _settings(monkeypatch, PROCEDURE_TENANT="tenant-composition")

    lookup = compose_procedures(StubRetriever(()), settings)

    assert lookup.scope.tenant_id == "tenant-composition"
    assert lookup.scope.clearance is AccessTier.RESTRICTED
