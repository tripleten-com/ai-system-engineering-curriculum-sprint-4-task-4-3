"""Coldline.

===================

File:              tests/contract/test_output_audit.py
Component:         Contract tests — Output validation and audit
Purpose:           One assessed check per public Check-list row that reads the running stack:
                    the stored outcome of each supplied response, the audit trail, the absence
                    of credentials, and the inherited Task 2 access rule.
Interacts With:    The running API, worker and PostgreSQL, tests/security/live_record.py,
                    tests/security/trail.py, tests/security/interaction.py,
                    src/worker/use_cases.py, src/api/routes.py (through the stack)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Fail-safe output handling, reconstructing one interaction, credentials never
                    recorded, inherited controls
Tools:             Python 3.12, pytest, httpx

Assessed: a fresh starter stores whatever the provider returned and records no audit
event, so most rows here fail until ``src/worker/use_cases.py`` and ``src/api/routes.py``
are complete. ``poe contract`` deselects them; ``poe output-contract`` and ``poe verify``
run them, right after the smoke checks and before the inherited end-to-end checks and the
student tests, so a wrong outcome is reported by the row that names it.

One module-scoped fixture, ``interactions``, is the trusted harness of the live rows: for
each supplied response it submits one reading through the open intake in a trace id of its
own choosing, waits through the database for a finished state, and makes exactly one
authenticated read of the record through the API, as the dispatcher, again in a trace id
of its own. Every live row then judges one of those three interactions on its own: no row
depends on another row having run, and each trail is checked independently. The rows
never read a record's state through the route the students edit, and they read the trail
back through the API container, as ``poe audit-trail`` does. The read-eligibility rows run
the in-process harness, because they need records in every state, a lookup that finds
nothing, and a refused request.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest

from adapters.model.deterministic import (
    PLANTED_FIELD,
    PLANTED_NEXT_STEP,
    PLANTED_VALUE,
    RESPONSES,
)
from common.audit import STORED_OUTCOME_STATES, AuditEvent
from domain.contracts import ExceptionState, SensorReading
from tests.contract.submission_validation import SubmissionError, validate_submission
from tests.runtime_config import host_port
from tests.security import live_record, trail
from tests.security.fixtures import EXPECTED_STATUS, FIXTURE_NAMES, bearer_headers, token
from tests.security.harness import TASK_ROOT
from tests.security.interaction import (
    InteractionHarness,
    place_record,
    replayed_answer,
    secret_values,
)
from worker.guardrail import REASON_CODES, REVIEW_MESSAGE, ValidatedSummary, validate_summary

pytestmark = pytest.mark.assessed
ROUTE = "/api/v1/exceptions/{exception_id}"
DISPATCHER = "dispatcher-valid"
DISPATCHER_SUBJECT = "user:dispatcher-01"
DISPATCHER_ROLE = "dispatcher"
BAD_RESPONSES = tuple(name for name in RESPONSES if name != "valid")
# The code the supplied guardrail reports for each supplied bad response.
EXPECTED_CODE = {"malformed": "not_json", "manipulated": "unknown_property"}
# The validation event each supplied response must produce.
EXPECTED_DECISION = {
    "valid": AuditEvent.OUTPUT_VALIDATED.value,
    "malformed": AuditEvent.OUTPUT_REJECTED.value,
    "manipulated": AuditEvent.OUTPUT_REJECTED.value,
}
# Text the emulator's answers carry and a stored record of a rejected answer must not.
MODEL_TEXT = (
    "Synthetic shipment",
    "thermal_excursion",
    "operational_review",
    PLANTED_FIELD,
    PLANTED_VALUE,
    PLANTED_NEXT_STEP,
    '"summary"',
)


@dataclass(frozen=True)
class Interaction:
    """One supplied response through the running stack, as the trusted harness made it.

    ``submission`` holds the reading, its ids, and the trace id the intake request was
    sent in; ``state`` is the finished state the database reported; ``read_trace_id`` is
    the trace id the one authenticated read was sent in, and ``body`` what it returned.
    """

    response: str
    submission: live_record.Submission
    state: str
    read_trace_id: str
    body: dict[str, Any]

    @property
    def exception_id(self) -> str:
        """Return the exception the interaction created."""
        return self.submission.exception_id

    def expected(self, record: dict[str, Any]) -> trail.ExpectedInteraction:
        """Return what the trail must agree with, from the harness's own knowledge only.

        The raw answer is replayed through the real emulator for the request the worker
        sent; the state and summary are the database's; the subject and role are the
        dispatcher fixture's.
        """
        answer = replayed_answer(
            exception_id=self.exception_id,
            reading=SensorReading.model_validate(self.submission.reading),
        )
        summary = record.get("summary")
        return trail.ExpectedInteraction(
            exception_id=self.exception_id,
            reading_id=self.submission.reading_id,
            provider=answer.provider,
            answer_text=answer.text,
            state=str(record.get("state")),
            summary=summary if isinstance(summary, str) else None,
            subject=DISPATCHER_SUBJECT,
            role=DISPATCHER_ROLE,
        )


@pytest.fixture(scope="module")
def api() -> Iterator[httpx.Client]:
    """Return a client for the running API on the host."""
    port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{port}", timeout=10.0) as client:
        yield client


def _read_once(api: httpx.Client, exception_id: str, trace_id: str) -> dict[str, Any]:
    """Read one record through the API as the dispatcher, once, in the given trace."""
    response = api.get(
        ROUTE.format(exception_id=exception_id),
        headers={**bearer_headers(DISPATCHER), **live_record.traceparent(trace_id)},
    )
    assert response.status_code == 200, _detail(response)
    body = response.json()
    assert isinstance(body, dict)
    return body


@pytest.fixture(scope="module")
def interactions(api: httpx.Client) -> dict[str, Interaction]:
    """Run one interaction per supplied response: submit, wait, and read once as the dispatcher.

    The wait ends on any finished state; which one each record reached is what the rows
    assert. The one read per record is made here, with a trace id of the harness's own,
    so every trail holds the worker's events and exactly one summary read before any
    row looks at it. A record that never finishes is an error on every row, not a row's
    failure.
    """
    made: dict[str, Interaction] = {}
    for response in RESPONSES:
        try:
            submission, state = live_record.create_finished_submission(api, response=response)
        except live_record.StoredRecordError as exc:
            raise RuntimeError(f"the live rows' precondition was not met: {exc}") from exc
        read_trace_id = live_record.new_trace_id()
        body = _read_once(api, submission.exception_id, read_trace_id)
        made[response] = Interaction(response, submission, state, read_trace_id, body)
    return made


def _record(exception_id: str) -> dict[str, Any]:
    """Return one record's output fields from the database, or fail the row."""
    try:
        record = live_record.stored_record(exception_id)
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))
    if record is None:
        pytest.fail(f"exception {exception_id} is not in the database")
    return record


def _detail(response: httpx.Response) -> str:
    """Return the refusal's reason, or the status line, for an assertion message."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    return str(body)[:200]


def _trail(exception_id: str) -> list[dict[str, Any]]:
    """Return one exception's audit trail from the running stack, or fail the row."""
    try:
        return trail.fetch_trail(exception_id)
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))


# --- Steps 1 and 2: the stored outcome of each supplied response -----------------------------


@pytest.mark.runtime
def test_valid_response_completes_with_only_the_schema_fields(
    interactions: dict[str, Interaction],
) -> None:
    """The valid answer ends in `COMPLETED`, and the record holds its validated fields only.

    The summary is the validated `summary` field of the answer the emulator gave (not the
    raw document, not the fixed message), `handling_class` and `next_step` are the
    validated values, and the rejection field is empty.
    """
    interaction = interactions["valid"]
    assert interaction.state == "COMPLETED", f"the valid response ended in {interaction.state}"
    record = _record(interaction.exception_id)
    summary = record.get("summary")
    assert isinstance(summary, str) and summary, "no summary was stored"
    assert not summary.lstrip().startswith("{"), "the raw answer document was stored as summary"
    assert '"summary"' not in summary and summary != REVIEW_MESSAGE
    expected = interaction.expected(record)
    verdict = validate_summary(expected.answer_text)
    assert isinstance(verdict, ValidatedSummary), expected.answer_text[:80]
    assert summary == verdict.summary, (
        "the stored summary is not the validated `summary` of the answer the emulator gave "
        "this request (the harness replays the emulator over the reading and the planted "
        f"procedure the stack retrieves for it): stored {summary!r}, expected "
        f"{verdict.summary!r}"
    )
    assert record.get("handling_class") == "thermal_excursion", (
        "the validated handling_class was not stored: route the answer through "
        "validate_summary and store the validated fields on the COMPLETED transition"
    )
    assert record.get("next_step") == "operational_review"
    assert record.get("rejection_reason") is None
    assert record.get("failure_reason") is None


@pytest.mark.runtime
@pytest.mark.parametrize("response", BAD_RESPONSES)
def test_bad_response_needs_review_with_the_fixed_message_and_none_of_the_models_text(
    interactions: dict[str, Interaction], response: str
) -> None:
    """The malformed and manipulated answers each end in `NEEDS_REVIEW` with the policy's outcome.

    The summary is the fixed message, the rejection reason is the guardrail's code for that
    answer, the validated fields are empty, and no stored field carries the model's text.
    """
    interaction = interactions[response]
    assert interaction.state == "NEEDS_REVIEW", (
        f"the {response} response ended in {interaction.state}"
    )
    record = _record(interaction.exception_id)
    assert record.get("summary") == REVIEW_MESSAGE, f"summary is {record.get('summary')!r}"
    reason = record.get("rejection_reason")
    assert isinstance(reason, str) and reason.split(":")[0] in REASON_CODES, reason
    assert reason.split(":")[0] == EXPECTED_CODE[response], reason
    assert record.get("handling_class") is None and record.get("next_step") is None
    assert record.get("failure_reason") is None
    for field, value in record.items():
        if isinstance(value, str) and field != "summary":
            for text in MODEL_TEXT:
                assert text not in value, f"{field} carries the model's text ({text!r})"


# --- Step 3: the audit trail --------------------------------------------------------------


@pytest.mark.runtime
@pytest.mark.parametrize("response", RESPONSES)
def test_the_audit_trail_reconstructs_one_interaction_in_order_with_trace_ids(
    interactions: dict[str, Interaction], response: str
) -> None:
    """Each supplied response's trail is the four worker events, in order, then the one read.

    Judged per response, against what the harness knows without the trail: every record
    names the exception; the worker's events carry the trace id the reading was
    submitted in and the read the trace id it was requested in; each worker event
    carries exactly the fields the event list permits, as scalars, with the values the
    harness captured independently (the reading id, the provider, the digest and length
    of the raw answer replayed through the real emulator, the real guardrail's decision
    and reason code over that answer, the stored state and summary from the database);
    and the read carries the dispatcher's subject and role. For `malformed` the third
    event is `output_rejected` with the reason `not_json`.
    """
    interaction = interactions[response]
    assert interaction.body.get("state") == interaction.state
    record = _record(interaction.exception_id)
    records = _trail(interaction.exception_id)
    assert records, (
        f"no audit records for {interaction.exception_id}: the worker recorded no event and "
        "the route recorded no summary read"
    )

    findings = trail.sequence_findings(records, reads=1)
    assert findings == [], "; ".join(findings) + f"\n{trail.events_of(records)}"
    findings = trail.field_findings(records)
    assert findings == [], "; ".join(findings)
    expected = interaction.expected(record)
    findings = trail.value_findings(records, expected)
    assert findings == [], "; ".join(findings)
    findings = trail.trace_findings(
        records, submission=interaction.submission.trace_id, reads=(interaction.read_trace_id,)
    )
    assert findings == [], "; ".join(findings)

    events = trail.events_of(records)
    assert events[2] == EXPECTED_DECISION[response], events
    third = trail.details_of(records[2])
    if response == "valid":
        assert third == {"handling_class": "thermal_excursion", "next_step": "operational_review"}
    else:
        assert third == {"reason_code": EXPECTED_CODE[response]}, third
        assert record.get("rejection_reason") == EXPECTED_CODE[response]
    outcome = trail.details_of(records[3])
    assert outcome == {"state": interaction.state, "summary": record.get("summary")}, outcome
    read = trail.details_of(records[4])
    assert read.get("subject") == DISPATCHER_SUBJECT and read.get("role") == DISPATCHER_ROLE, read
    requested = trail.details_of(records[0])
    assert requested.get("reading_id") == interaction.submission.reading_id, requested
    assert not any(key in requested for key in ("subject", "role", "token"))


@pytest.mark.runtime
def test_no_audit_record_contains_a_credential(interactions: dict[str, Interaction]) -> None:
    """No record of any supplied response's trail holds a token, a header name, or a secret.

    Each trail holds the worker's events and the one summary read the harness made; every
    record is rendered whole and searched, and every summary read is held to its two
    permitted fields, as scalars: a request header, or anything else from the request,
    under any name is a credential finding.
    """
    for response in RESPONSES:
        exception_id = interactions[response].exception_id
        records = _trail(exception_id)
        assert records, f"{response}: no audit records to check: the worker recorded no event"
        findings = trail.credential_findings(
            records, token=token(DISPATCHER), secrets=secret_values()
        )
        findings.extend(trail.read_field_findings(records))
        assert findings == [], f"{response}: " + "; ".join(findings)


@pytest.mark.runtime
def test_each_summary_read_carries_its_own_requests_trace_id(api: httpx.Client) -> None:
    """Two reads of one exception leave two reads with two distinct trace ids: their requests'.

    A fresh interaction, self-contained: the reading is submitted in one trace, the record
    is read twice as the dispatcher in two more, and the trail's worker events carry the
    first while the two summary reads carry the second and the third, in order.
    """
    try:
        submission, state = live_record.create_finished_submission(api, response="valid")
    except live_record.StoredRecordError as exc:
        pytest.fail(f"the trace row's precondition was not met: {exc}")
    assert state in {item.value for item in STORED_OUTCOME_STATES}, state
    first, second = live_record.new_trace_id(), live_record.new_trace_id()
    _read_once(api, submission.exception_id, first)
    _read_once(api, submission.exception_id, second)

    records = _trail(submission.exception_id)
    assert records, f"no audit records for {submission.exception_id}"
    findings = trail.sequence_findings(records, reads=2)
    assert findings == [], "; ".join(findings) + f"\n{trail.events_of(records)}"
    findings = trail.trace_findings(records, submission=submission.trace_id, reads=(first, second))
    assert findings == [], "; ".join(findings)
    read_ids = [
        record.get("trace_id")
        for record in records
        if record.get("event") == AuditEvent.SUMMARY_READ.value
    ]
    assert read_ids == [first, second] and first != second, read_ids


# --- Step 3: when a read is a summary read ------------------------------------------------


def _eligibility_cases() -> list[Any]:
    """Return one case per state and summary presence, plus a missing record and a refusal."""
    cases: list[Any] = []
    for state in ExceptionState:
        for stored in (True, False):
            label = "stored" if stored else "no-summary"
            cases.append(pytest.param(state, stored, DISPATCHER, id=f"{state.value}-{label}"))
    cases.append(pytest.param(None, True, DISPATCHER, id="missing"))
    cases.append(pytest.param(ExceptionState.COMPLETED, True, "expired", id="refused"))
    return cases


@pytest.fixture(scope="module")
def in_process() -> InteractionHarness:
    """Return one in-process API and worker, over a memory store and a memory audit sink."""
    return InteractionHarness()


@pytest.mark.runtime
@pytest.mark.parametrize(("state", "stored", "fixture"), _eligibility_cases())
async def test_summary_read_is_recorded_only_for_a_read_that_returned_a_stored_outcome(
    in_process: InteractionHarness, state: ExceptionState | None, stored: bool, fixture: str
) -> None:
    """Exactly one read for a stored outcome; none for any other state, a 404, or a refusal.

    In-process, over the real route: a record in each of the six states, with and without
    a stored summary, is read once as the dispatcher. Only `COMPLETED` and `NEEDS_REVIEW`
    with a summary leave exactly one `summary_read`, with the subject and the role; every
    other combination, a lookup that finds nothing, and a refused request (an `expired`
    token on a stored outcome) leave no audit record at all.
    """
    if state is None:
        exception_id = f"exc-missing-{live_record.new_trace_id()[:12]}"
        expected_status = 404
    else:
        summary: str | None = None
        if stored:
            summary = REVIEW_MESSAGE if state is ExceptionState.NEEDS_REVIEW else "Stored summary."
        exception_id = place_record(
            in_process,
            state,
            summary=summary,
            rejection_reason="not_json" if state is ExceptionState.NEEDS_REVIEW else None,
        )
        expected_status = 200 if fixture == DISPATCHER else EXPECTED_STATUS[fixture]
    async with in_process.bearer_client(fixture) as client:
        response = await client.get(ROUTE.format(exception_id=exception_id))
    assert response.status_code == expected_status, _detail(response)

    records = in_process.audit_trail(exception_id)
    eligible = state in STORED_OUTCOME_STATES and stored and fixture == DISPATCHER
    reads = [entry for entry in records if entry.event == AuditEvent.SUMMARY_READ.value]
    assert [entry.event for entry in records] == [entry.event for entry in reads], (
        f"the route recorded events other than summary_read: {[entry.event for entry in records]}"
    )
    assert len(reads) == (1 if eligible else 0), (
        f"expected {'exactly one' if eligible else 'no'} summary_read after one read of a "
        f"{state.value if state else 'missing'} record "
        f"{'with' if stored else 'without'} a summary as {fixture}, found {len(reads)}"
    )
    if eligible:
        assert reads[0].details.get("subject") == DISPATCHER_SUBJECT
        assert reads[0].details.get("role") == DISPATCHER_ROLE


# --- The inherited Task 2 control ---------------------------------------------------------


@pytest.mark.runtime
def test_the_task_2_access_rule_still_protects_the_summary_route(api: httpx.Client) -> None:
    """`dispatcher-valid` reads `200`; the seven other fixtures and a bare request are refused.

    The settled rule from Task 4.2 is supplied code in this Task; the route edit this Task
    asks for must leave it in place. The exception is created through the open intake and
    confirmed through the database to hold a stored summary before the first request.
    """
    try:
        exception_id = live_record.create_stored_exception(api)
    except live_record.StoredRecordError as exc:
        pytest.fail(f"the access row's precondition was not met: {exc}")
    for fixture in FIXTURE_NAMES:
        response = api.get(ROUTE.format(exception_id=exception_id), headers=bearer_headers(fixture))
        assert response.status_code == EXPECTED_STATUS[fixture], (
            f"{fixture}: {response.status_code} {_detail(response)}"
        )
        if EXPECTED_STATUS[fixture] != 200:
            assert "exception_id" not in response.text, f"{fixture}: the record was returned"
    bare = api.get(ROUTE.format(exception_id=exception_id))
    assert bare.status_code == 401, f"no token: {bare.status_code} {_detail(bare)}"
    assert "exception_id" not in bare.text


# --- The answer sheet ----------------------------------------------------------------------


def test_submission_records_no_answers() -> None:
    """`submission.yaml` still records `answers: {}` and passes the public format check."""
    try:
        validate_submission(
            TASK_ROOT / "submission.yaml",
            TASK_ROOT / "docs/contracts/submission.schema.json",
            task_root=TASK_ROOT,
        )
    except SubmissionError as exc:
        pytest.fail(str(exc))
