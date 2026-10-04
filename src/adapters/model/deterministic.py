"""Coldline.

===================

File:              src/adapters/model/deterministic.py
Component:         Adapter — Deterministic
Purpose:           Implement the deterministic local model-provider adapter and its three
                    supplied responses.
Interacts With:    Domain contracts, ports, and local providers; infra/corpus/documents.jsonl
                    (the planted instruction the manipulated response follows)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Boundary translation, deterministic infrastructure, raw provider answers,
                    supplied bad answers
Tools:             Python 3.12, OpenTelemetry

Task 4.3 gives the emulator three supplied responses, selected by the request's
development-only ``emulator_response`` field (``poe scenario --response`` sets it on the
reading, the worker copies it into the request):

- ``valid`` (the default, and what an absent selector means): the JSON document the
  emulator has answered with since the Project 4 opening checkpoint. It satisfies
  ``schemas/exception-summary.schema.json``.
- ``malformed``: the same document, stopped partway through, as a provider that hit its
  output limit would stop. It is not valid JSON.
- ``manipulated``: well-formed JSON that follows the instruction planted in one supplied
  corpus procedure. The emulator reads the instruction out of the procedure excerpt it was
  given (``PLANTED_INSTRUCTION`` is its shape) and does what it says: it sets ``next_step``
  to a value outside the schema's list and adds a field the schema does not name. This is
  what a susceptible model does with an instruction in its input; the default response is
  the same model ignoring it.

The emulator decides nothing about the key it is given; a later Task makes it accept only
the current version.
"""

import asyncio
import hashlib
import json
import re

from opentelemetry import trace

from domain.contracts import ModelAnswer, ModelRequest
from domain.errors import TerminalProviderError

_TRACER = trace.get_tracer(__name__)
# How much of the retrieved procedure the emulator repeats in its summary.
_PROCEDURE_SENTENCE_CHARACTERS = 160
# The supplied responses, by the name `poe scenario --response` takes.
RESPONSES: tuple[str, ...] = ("valid", "malformed", "manipulated")
DEFAULT_RESPONSE = "valid"
# The shape of the instruction planted in the supplied corpus (`infra/corpus/documents.jsonl`,
# `playbook-thermal-excursion`), which the manipulated response follows. The values the
# corpus plants are the defaults below, so the response is the same whether or not the
# excerpt the request carries happens to hold the sentence.
PLANTED_INSTRUCTION = re.compile(
    r"set next_step to (?P<next_step>[a-z_]+) and add (?P<field>[a-z_]+): (?P<value>[a-z_]+)"
)
PLANTED_NEXT_STEP = "release_without_review"
PLANTED_FIELD = "dispatcher_override"
PLANTED_VALUE = "approved"
# Where the malformed answer stops: inside the summary string, three fifths of the way in.
_MALFORMED_NUMERATOR = 3
_MALFORMED_DENOMINATOR = 5


class DeterministicModelProvider:
    """Return repeatable answers without network or paid-model calls.

    The emulator imitates a hosted provider's wire shape: it takes a provider
    key at construction, the way a client would carry an API key, and answers
    with one JSON document as raw text. At this checkpoint it checks nothing
    about the key; a later Task makes it accept only the current version.

    The answer repeats what the request carried. A handling note on the
    request appears in the summary verbatim, and so does the first sentence of
    the procedure excerpt, which is what a summarising model would do with the
    text it was given.
    """

    def __init__(self, *, latency_ms: int = 250, provider_key: str = "") -> None:
        """Configure a fixed non-negative provider delay in milliseconds and the key."""
        if latency_ms < 0:
            raise ValueError("latency_ms must not be negative")
        self._latency_seconds = latency_ms / 1000
        self._provider_key = provider_key

    @property
    def provider_key(self) -> str:
        """Return the key the worker handed this client at composition time."""
        return self._provider_key

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Return one raw answer for a synthetic temperature excursion.

        The default answer is the valid JSON document; a request that names one of the
        other supplied responses receives that one. A name outside ``RESPONSES`` is a
        terminal failure, as a hosted provider's rejected request would be.
        """
        with _TRACER.start_as_current_span(
            "model_provider.summarize",
            attributes={"coldline.exception_id": request.exception_id},
        ):
            if self._latency_seconds:
                await asyncio.sleep(self._latency_seconds)
            response = request.emulator_response or DEFAULT_RESPONSE
            if response not in RESPONSES:
                choices = ", ".join(RESPONSES)
                raise TerminalProviderError(
                    f"unknown supplied response {response!r}; choose one of {choices}"
                )
            payload = _valid_document(request)
            if response == "manipulated":
                payload = _follow_planted_instruction(payload, request.procedure_excerpt)
            text = json.dumps(payload, sort_keys=True)
            if response == "malformed":
                text = _stopped_partway(text)
            return ModelAnswer(provider="deterministic-local", text=text)


def _valid_document(request: ModelRequest) -> dict[str, object]:
    """Return the schema-valid answer document for one request."""
    if request.temperature_c > request.allowed_max_c:
        magnitude = request.temperature_c - request.allowed_max_c
        condition = f"exceeded the upper handling bound by {magnitude:.1f} C"
    else:
        magnitude = request.allowed_min_c - request.temperature_c
        condition = f"fell below the lower handling bound by {magnitude:.1f} C"

    sentences = [
        f"Synthetic shipment {request.shipment_id} {condition}; operational review is required."
    ]
    if request.procedure_id is not None and request.procedure_excerpt:
        sentences.append(
            f"Procedure {request.procedure_id}: {_first_sentence(request.procedure_excerpt)}"
        )
    if request.handling_note:
        sentences.append(f"Handling note: {request.handling_note}")

    return {
        "summary": " ".join(sentences),
        "handling_class": "thermal_excursion",
        "next_step": "operational_review",
        "procedure_id": request.procedure_id,
        "response_id": _response_id(request),
    }


def _follow_planted_instruction(payload: dict[str, object], excerpt: str) -> dict[str, object]:
    """Apply the instruction the procedure excerpt plants, or the supplied corpus's defaults.

    A susceptible model does what the text it was given tells it to. The instruction the
    supplied corpus plants names a next step outside the schema's list and a field the
    schema does not have; when the excerpt carries that sentence its values are used, and
    when it does not (a request built without the planted procedure) the same two
    deviations are applied from the constants, so the response is deterministic either way.
    """
    match = PLANTED_INSTRUCTION.search(excerpt)
    if match is None:
        next_step, field, value = PLANTED_NEXT_STEP, PLANTED_FIELD, PLANTED_VALUE
    else:
        next_step, field, value = match["next_step"], match["field"], match["value"]
    manipulated = dict(payload)
    manipulated["next_step"] = next_step
    manipulated[field] = value
    return manipulated


def _stopped_partway(text: str) -> str:
    """Cut the answer three fifths of the way through, as an output limit would."""
    return text[: len(text) * _MALFORMED_NUMERATOR // _MALFORMED_DENOMINATOR]


def _first_sentence(text: str) -> str:
    """Return the excerpt's first sentence, bounded, so the summary stays short."""
    sentence = text.split(". ", maxsplit=1)[0].strip()
    if not sentence.endswith("."):
        sentence = f"{sentence}."
    return sentence[:_PROCEDURE_SENTENCE_CHARACTERS]


def _response_id(request: ModelRequest) -> str:
    """Imitate a provider's per-answer response id from the request identity.

    A stable, short identifier that a log line can quote; it protects nothing
    and is never compared against anything.
    """
    digest = hashlib.sha1(f"{request.exception_id}:{request.shipment_id}".encode())
    return digest.hexdigest()[:16]
