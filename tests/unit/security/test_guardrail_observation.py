"""Coldline.

===================

File:              tests/unit/security/test_guardrail_observation.py
Component:         Unit tests — Trusted guardrail observation
Purpose:           Prove the observation names a worker that parses the provider's answer on
                    its own behind a dummy guardrail call, and one that hands the answer over
                    and then ignores the verdict, in this process, with no stack.
Interacts With:    tests/security/guardrail_observation.py, tests/security/interaction.py,
                    tests/security/guardrail_binding.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Behavioural evidence beside static evidence, spies at a verified binding,
                    inverted verdicts, counterexamples that static rules accept
Tools:             Python 3.12, pytest, asyncio

The two workers here are probes: source text in this file, executed into a module of its
own, the way an import would bind it. Neither is the Task's worker, and the shipped
``src/worker/use_cases.py`` is never read or run here (the assessed row runs it). Both are
counterexamples the static binding check accepts, which is the point of the observation:
each spells the one permitted import and uses ``validate_summary`` only as a callee, so
only what happens at run time tells them from a worker that routes every answer through
the supplied guardrail and stores what it answered. No correct worker is built here; the
student's own is judged by the assessed row, not by a probe.
"""

from __future__ import annotations

from types import ModuleType

import pytest

from adapters.model.deterministic import RESPONSES
from domain.contracts import ExceptionState
from tests.security import guardrail_binding as binding
from tests.security import guardrail_observation as observation
from tests.security.interaction import TASK_ROOT

# What both probes share: the harness's constructor signature, one provider call built as
# the worker builds it, and the permitted import. Each probe adds its own ending.
_WORKER_BODY = '''
from domain.contracts import ExceptionState, ModelRequest
from worker.guardrail import validate_summary


class WorkerApplication:
    """The smallest worker the harness can run; it implements no output policy."""

    def __init__(self, repository, provider, procedures, *, audit, clock, maximum_attempts=3):
        """Keep the collaborators the harness hands over."""
        self._repository = repository
        self._provider = provider
        self._procedures = procedures

    async def process(self, job, *, delivery_count):
        """Call the provider once, then do what this probe does with its answer."""
        await self._repository.transition(
            job.exception_id, {ExceptionState.QUEUED}, ExceptionState.PROCESSING
        )
        procedure = await self._procedures.find(job.reading)
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
'''

# Counterexample 1: one guardrail call as a switch, handed a constant, and the provider's
# real answer parsed by the worker itself. The live rows would see a stored summary; the
# bypass mutation would still make the probe's own parsing disappear with the call.
OWN_PARSING_WORKER = (
    '"""Probe worker: a dummy guardrail call, the real answer parsed on its own."""\n\n'
    "import json\n"
    + _WORKER_BODY
    + """        validate_summary("{}")
        try:
            parsed = json.loads(answer.text)
        except ValueError:
            parsed = {}
        summary = parsed.get("summary", answer.text) if isinstance(parsed, dict) else answer.text
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=summary,
        )
        return "ACK"
"""
)

# Counterexample 2: the answer is handed over exactly as it should be, and the verdict is
# dropped on the floor; the raw text is stored as the summary whatever the guardrail said.
VERDICT_IGNORING_WORKER = (
    '"""Probe worker: the answer handed over once, the verdict ignored, the text stored."""\n'
    + _WORKER_BODY
    + """        validate_summary(answer.text)
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=answer.text,
        )
        return "ACK"
"""
)

FOLLOW_HINT = "the stored outcome must follow the guardrail's verdict"
HAND_OVER_HINT = "the raw answer text itself must reach the guardrail"


def _probe_module(source: str, name: str) -> ModuleType:
    """Execute one probe's source into a module of its own, as an import would bind it."""
    module = ModuleType(name)
    exec(compile(source, f"<{name}>", "exec"), module.__dict__)
    return module


@pytest.mark.parametrize(
    "source", [OWN_PARSING_WORKER, VERDICT_IGNORING_WORKER], ids=["own-parsing", "verdict-ignored"]
)
def test_both_counterexamples_pass_the_static_binding_check(source: str) -> None:
    """Each probe spells the permitted import and calls the name: the static rules see nothing.

    This is why the observation exists: the binding check proves what the name is bound
    to and that every use is a call, not what the call is handed or what the worker does
    with the answer.
    """
    assert binding.findings_for_source(source) == []


async def test_a_dummy_guardrail_call_beside_own_parsing_is_named_for_every_response() -> None:
    """A worker that hands the guardrail a constant and parses the answer itself fails hand-over.

    Each response gives one finding naming what the guardrail was handed (two characters)
    against what the provider answered; the inverted runs are not made, because an answer
    that never reached the guardrail leaves nothing for a stood-in verdict to show. The
    stored record alone would not have told: the probe ends ``COMPLETED`` with a summary.
    """
    module = _probe_module(OWN_PARSING_WORKER, "probe_own_parsing")

    observed = await observation.observe(module, "valid", root=TASK_ROOT)
    assert observed.record.state is ExceptionState.COMPLETED
    assert observed.record.summary
    assert observed.calls == ((("{}",), {}),)
    assert len(observed.answers) == 1 and observed.answers[0] != "{}"

    findings = await observation.observe_module(module, root=TASK_ROOT)

    assert len(findings) == len(RESPONSES)
    for response, finding in zip(RESPONSES, findings, strict=True):
        assert finding.startswith(
            f"{response}: `validate_summary` was handed a string of 2 characters"
        ), finding
        assert "not the provider's answer (a string of " in finding
        assert HAND_OVER_HINT in finding
        assert FOLLOW_HINT not in finding


async def test_a_worker_that_ignores_the_verdict_fails_only_the_inverted_runs() -> None:
    """A worker that hands the answer over and stores the text regardless fails on the verdict.

    Hand-over is clean for every response: one provider call, one guardrail call, with the
    captured answer text as the one argument. Under the inverted verdicts the record does
    not follow: the valid answer, answered with a rejection, is still ``COMPLETED``
    (the ``state`` finding), and each bad answer, answered with the valid answer's
    validated summary, keeps the raw text instead of the validated fields.
    """
    module = _probe_module(VERDICT_IGNORING_WORKER, "probe_verdict_ignored")
    original = module.validate_summary

    for response in RESPONSES:
        observed = await observation.observe(module, response, root=TASK_ROOT)
        assert observation.hand_over_findings(observed) == []
        assert observed.calls == (((observed.answers[0],), {}),)
        assert module.validate_summary is original
        with pytest.raises(observation.ObservationError, match="inverted run"):
            observation.followed_findings(observed)

    findings = await observation.observe_module(module, root=TASK_ROOT)

    assert findings
    assert all(FOLLOW_HINT in finding for finding in findings)
    assert not any(HAND_OVER_HINT in finding for finding in findings)
    code = observation.INVERTED_REJECTION.code
    assert (
        f"valid: with `validate_summary` answering a rejection ({code}), the stored record's "
        f"state is 'COMPLETED', expected 'NEEDS_REVIEW'; {FOLLOW_HINT}"
    ) in findings
    assert (
        f"valid: with `validate_summary` answering a rejection ({code}), the stored record's "
        f"rejection_reason is None, expected {code!r}; {FOLLOW_HINT}"
    ) in findings
    for response in ("malformed", "manipulated"):
        about = [finding for finding in findings if finding.startswith(f"{response}: ")]
        assert about, response
        assert all("answering a validated summary" in finding for finding in about)
        assert not any("record's state is" in finding for finding in about)
        assert any("record's summary is" in finding for finding in about)
        assert any("record's handling_class is None" in finding for finding in about)
        assert any("record's next_step is None" in finding for finding in about)
    assert module.validate_summary is original
