"""Coldline.

===================

File:              tests/security/guardrail_observation.py
Component:         Security tooling — Trusted guardrail observation
Purpose:           Run the student's worker in this process with the provider's answers captured
                    and the supplied guardrail stood in for, and judge that every answer reaches
                    the guardrail unchanged and that the stored outcome follows its verdict.
Interacts With:    src/worker/use_cases.py, src/worker/guardrail.py, tests/security/interaction.py,
                    tests/security/guardrail_binding.py, tests/contract/test_negative_tests.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Behavioural evidence beside static evidence, spies at a verified binding,
                    inverted verdicts
Tools:             Python 3.12, asyncio

The static check in ``tests/security/guardrail_binding.py`` proves that the worker's
``validate_summary`` is the supplied guardrail's import and that every use of the name is
a call. It cannot prove what the call is handed, or what the worker does with the answer.
A worker could call ``validate_summary("{}")`` once as a switch (rejected as written,
accepted under the ``validation-bypass`` mutation), parse the provider's real answer on its
own, and store its own verdict: the live rows would see the right records, the mutation
rows would see both bad-answer tests fail, and the schema would never have seen an answer.
Or a worker could hand the answer over correctly and then ignore what came back.

This module closes both gaps from the behavioural side, in this process, with no stack:

1. **Hand-over.** For each supplied response the student's worker is run once through
   the trusted harness (``interaction.run_application``) with the emulator wrapped so
   the raw answer it returned is captured, and with ``worker.use_cases.validate_summary``
   replaced for the duration of the run by a spy that records each call and answers with
   the real guardrail's verdict. The spy must have been called exactly once, with that
   captured answer text as its one argument (``validate_summary(answer.text)``: no other
   argument, so the supplied schema is the one applied), and the provider exactly once.
2. **Verdict followed.** Then each response is run again with the spy answering a fixed,
   inverted verdict: a ``RejectedSummary`` for the valid answer, and the
   ``ValidatedSummary`` the real guardrail gives the valid answer for each bad answer.
   The record the worker leaves must follow that verdict and nothing else: ``NEEDS_REVIEW``
   with the fixed message and the rejection's code, or ``COMPLETED`` with the validated
   summary, handling class and next step.

The binding check runs first and the static rules must pass before this module imports
the worker, so a worker that spells a door to the runner is named before anything of it
executes. What this module cannot see is a worker that reaches the runner through objects
the harness itself hands in without spelling an import or a dynamic name; that residual
is recorded with the review, and the committed tree is what the instructor reads.
"""

from __future__ import annotations

import asyncio
import importlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from adapters.model.deterministic import RESPONSES
from common.audit import answer_digest
from domain.contracts import ExceptionRecord, ExceptionState, ModelAnswer, ModelRequest
from ports import ModelProvider
from tests.security.harness import TASK_ROOT
from tests.security.interaction import InteractionHarness, run_application
from worker.guardrail import REVIEW_MESSAGE, RejectedSummary, ValidatedSummary, validate_summary

WORKER_MODULE = "worker.use_cases"
GUARDRAIL_NAME = "validate_summary"
APPLICATION_NAME = "WorkerApplication"
RAW_PARAMETER = "raw"
# The verdict the valid answer is answered with in the inverted run: a rejection with a
# field suffix, so a worker that stores the code stores the whole code.
INVERTED_REJECTION = RejectedSummary("value_not_permitted", "next_step")
Verdict = ValidatedSummary | RejectedSummary
Call = tuple[tuple[object, ...], dict[str, object]]


class ObservationError(RuntimeError):
    """Report that the worker could not be observed, as opposed to a finding about it."""


class CapturingProvider:
    """Wrap the harness's emulator and keep every raw answer it returned to the worker."""

    def __init__(self, inner: ModelProvider) -> None:
        """Wrap one provider."""
        self._inner = inner
        self.answers: list[ModelAnswer] = []

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Return the wrapped provider's answer and keep it."""
        answer = await self._inner.summarize(request)
        self.answers.append(answer)
        return answer


@dataclass
class GuardrailSpy:
    """Stand in for ``validate_summary`` in the worker module for one run.

    Every call is recorded with its positional and keyword arguments. With no fixed
    ``verdict`` the real guardrail answers; with one, that verdict is returned whatever
    the worker handed over.
    """

    inner: Callable[..., Verdict]
    verdict: Verdict | None = None
    calls: list[Call] = field(default_factory=list)

    def __call__(self, *args: object, **kwargs: object) -> Verdict:
        """Record the call and answer."""
        self.calls.append((args, dict(kwargs)))
        if self.verdict is not None:
            return self.verdict
        return self.inner(*args, **kwargs)


@dataclass(frozen=True)
class Observation:
    """What one observed run showed: the answers, the guardrail calls, the record, the verdict.

    ``verdict`` is the stood-in verdict of an inverted run, or None when the real
    guardrail answered.
    """

    response: str
    answers: tuple[str, ...]
    calls: tuple[Call, ...]
    record: ExceptionRecord
    verdict: Verdict | None = None


def _describe(value: object) -> str:
    """Describe a value handed to the guardrail without quoting it."""
    if isinstance(value, str):
        return f"a string of {len(value)} characters (digest {answer_digest(value)[:12]})"
    return f"a {type(value).__name__}"


def load_worker_module(name: str = WORKER_MODULE) -> ModuleType:
    """Import the worker module and check it binds the guardrail's name and the application."""
    module = importlib.import_module(name)
    if not callable(getattr(module, GUARDRAIL_NAME, None)):
        raise ObservationError(f"{name} binds no callable `{GUARDRAIL_NAME}`")
    if not callable(getattr(module, APPLICATION_NAME, None)):
        raise ObservationError(f"{name} defines no `{APPLICATION_NAME}`")
    return module


async def observe(
    module: ModuleType,
    response: str,
    *,
    root: Path = TASK_ROOT,
    verdict: Verdict | None = None,
    harness: InteractionHarness | None = None,
) -> Observation:
    """Run the module's worker once with the named response, spied on, and return what happened.

    The module's ``validate_summary`` binding is replaced by the spy for the duration of
    the run and restored afterwards, whatever happens. The harness is a fresh in-process
    one over ``root`` unless given.
    """
    original = getattr(module, GUARDRAIL_NAME, None)
    application_class = getattr(module, APPLICATION_NAME, None)
    if not callable(original):
        raise ObservationError(f"{module.__name__} binds no callable `{GUARDRAIL_NAME}`")
    if not callable(application_class):
        raise ObservationError(f"{module.__name__} defines no `{APPLICATION_NAME}`")
    spy = GuardrailSpy(original, verdict)
    harness = InteractionHarness(root) if harness is None else harness
    provider = CapturingProvider(harness._emulator)
    setattr(module, GUARDRAIL_NAME, spy)
    try:
        record = await run_application(
            harness, response, application_class=application_class, provider=provider
        )
    finally:
        setattr(module, GUARDRAIL_NAME, original)
    return Observation(
        response=response,
        answers=tuple(answer.text for answer in provider.answers),
        calls=tuple(spy.calls),
        record=record,
        verdict=verdict,
    )


def hand_over_findings(observation: Observation) -> list[str]:
    """Return why the run did not hand the provider's one answer to the guardrail once, as is."""
    label = observation.response
    findings: list[str] = []
    if len(observation.answers) != 1:
        findings.append(
            f"{label}: the provider was called {len(observation.answers)} times during one "
            "processing; one call is expected"
        )
    if not observation.calls:
        findings.append(
            f"{label}: `{GUARDRAIL_NAME}` was not called: the provider's answer never reached "
            "the supplied guardrail"
        )
        return findings
    if len(observation.calls) != 1:
        findings.append(
            f"{label}: `{GUARDRAIL_NAME}` was called {len(observation.calls)} times during one "
            "processing; exactly one call, with the provider's answer, is expected"
        )
        return findings
    if not observation.answers:
        return findings
    args, kwargs = observation.calls[0]
    answer = observation.answers[0]
    handed = args[0] if args else kwargs.get(RAW_PARAMETER)
    extra: list[str] = []
    if len(args) > 1:
        extra.append(f"{len(args) - 1} extra positional argument(s)")
    extra.extend(f"`{name}=`" for name in sorted(kwargs) if args or name != RAW_PARAMETER)
    if extra:
        findings.append(
            f"{label}: `{GUARDRAIL_NAME}` was called with more than the answer "
            f"({', '.join(extra)}); call it as `{GUARDRAIL_NAME}(answer.text)` and nothing else, "
            "so the supplied schema is the one applied"
        )
    if handed != answer:
        findings.append(
            f"{label}: `{GUARDRAIL_NAME}` was handed {_describe(handed)}, not the provider's "
            f"answer ({_describe(answer)}); the raw answer text itself must reach the guardrail"
        )
    return findings


def followed_findings(observation: Observation) -> list[str]:
    """Return why the record does not follow the stood-in verdict of an inverted run."""
    verdict = observation.verdict
    if verdict is None:
        raise ObservationError("followed_findings needs an inverted run (a stood-in verdict)")
    record = observation.record
    if isinstance(verdict, RejectedSummary):
        kind = f"a rejection ({verdict.code})"
        expected: dict[str, object] = {
            "state": ExceptionState.NEEDS_REVIEW,
            "summary": REVIEW_MESSAGE,
            "rejection_reason": verdict.code,
            "handling_class": None,
            "next_step": None,
        }
    else:
        kind = "a validated summary"
        expected = {
            "state": ExceptionState.COMPLETED,
            "summary": verdict.summary,
            "handling_class": verdict.handling_class,
            "next_step": verdict.next_step,
            "rejection_reason": None,
        }
    findings: list[str] = []
    for name, value in expected.items():
        actual = getattr(record, name)
        if actual != value:
            shown = actual.value if isinstance(actual, ExceptionState) else actual
            wanted = value.value if isinstance(value, ExceptionState) else value
            findings.append(
                f"{observation.response}: with `{GUARDRAIL_NAME}` answering {kind}, the stored "
                f"record's {name} is {shown!r}, expected {wanted!r}; the stored outcome must "
                "follow the guardrail's verdict"
            )
    return findings


async def observe_module(module: ModuleType, *, root: Path = TASK_ROOT) -> list[str]:
    """Run both observations over one worker module and return every finding.

    The hand-over runs come first, one per response; the inverted runs are made only when
    every answer reached the guardrail as is, because a worker that parses on its own has
    already failed and its records under a stood-in verdict would say nothing new.
    """
    findings: list[str] = []
    answers: dict[str, str] = {}
    for response in RESPONSES:
        observation = await observe(module, response, root=root)
        findings.extend(hand_over_findings(observation))
        if observation.answers:
            answers[response] = observation.answers[0]
    if findings:
        return findings
    accepted = validate_summary(answers["valid"])
    if not isinstance(accepted, ValidatedSummary):
        raise ObservationError(
            "the supplied valid answer does not pass the supplied guardrail: "
            f"{accepted.code}; the inverted run has no validated verdict to stand in"
        )
    for response in RESPONSES:
        inverted: Verdict = INVERTED_REJECTION if response == "valid" else accepted
        observation = await observe(module, response, root=root, verdict=inverted)
        findings.extend(followed_findings(observation))
    return findings


def check(root: Path = TASK_ROOT) -> list[str]:
    """Import the student's worker and return every finding of both observations.

    For the assessed row: call it only after the static binding check has passed, so the
    import happens only for a worker that spells no door to the runner.
    """
    return asyncio.run(observe_module(load_worker_module(), root=root))
