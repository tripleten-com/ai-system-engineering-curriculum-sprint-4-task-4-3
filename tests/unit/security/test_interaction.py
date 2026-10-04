"""Coldline.

===================

File:              tests/unit/security/test_interaction.py
Component:         Unit tests — Interaction harness helpers
Purpose:           Prove the harness's supplied inputs are the running stack's: the planted
                    procedure, the scenario's reading, and the credential values.
Interacts With:    tests/security/interaction.py, infra/corpus/documents.jsonl,
                    tests/fixtures/credentials/test-values.yaml, tests/e2e/baseline-exception.json
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Deterministic test inputs that match the live stack
Tools:             Python 3.12, pytest

Nothing here constructs the harness or runs the worker: the worker's use cases are the
student's file, and the assessed rows are where its outcomes are judged.
"""

from __future__ import annotations

from datetime import UTC, datetime

from adapters.model.deterministic import PLANTED_INSTRUCTION
from common.audit import AuditRecord
from tests.security import interaction
from worker.procedures import EXCERPT_WORDS


def test_the_planted_excerpt_is_the_playbooks_first_chunk_with_the_instruction() -> None:
    """The excerpt names the playbook, is bounded as the lookup bounds it, and holds the plant."""
    excerpt = interaction.planted_excerpt()

    assert excerpt.found
    assert excerpt.document_id == interaction.PLANTED_DOCUMENT_ID
    assert excerpt.chunk_id == f"{interaction.PLANTED_DOCUMENT_ID}#0000"
    assert len(excerpt.text.split()) <= EXCERPT_WORDS
    assert excerpt.text.startswith("A thermal excursion begins")
    assert PLANTED_INSTRUCTION.search(excerpt.text) is not None
    assert excerpt.window_minutes is None


def test_the_scenario_reading_carries_a_fresh_identity_and_the_response() -> None:
    """Two readings differ in identity and share everything else from the fixture."""
    first = interaction.scenario_reading(response="malformed")
    second = interaction.scenario_reading(response="malformed")

    assert first.reading_id != second.reading_id
    assert first.shipment_id != second.shipment_id
    assert first.emulator_response == second.emulator_response == "malformed"
    assert first.temperature_c == 9.2 and first.allowed_max_c == 8.0
    assert first.handling_note == second.handling_note
    assert first.handling_note is not None and "Priya" in first.handling_note


def test_the_credential_values_are_the_four_the_stack_holds() -> None:
    """The fixture lists the provider key, the two LocalStack keys, and the database password."""
    values = interaction.secret_values()

    assert values == (
        "coldline-dev-provider-key-v1",
        "localstack-development-key",
        "localstack-development-secret",
        "coldline_local",
    )


def test_rendered_trail_joins_one_json_line_per_record() -> None:
    """The text a credential test searches is every record, one line each."""
    now = datetime(2026, 9, 1, tzinfo=UTC)
    records = [
        AuditRecord("a", "exc-1", None, now, {"k": "v"}, 1),
        AuditRecord("b", "exc-1", None, now, {}, 2),
    ]

    text = interaction.rendered_trail(records)

    assert text.count("\n") == 1
    assert '"event": "a"' in text and '"event": "b"' in text and '"k": "v"' in text
