"""Coldline.

===================

File:              tests/security/guardrail_mutation.py
Component:         Security tooling — Guardrail and audit mutations
Purpose:           Record what the student's guardrail and audit tests actually do, then rerun
                    them against mutated copies of the worker and the route.
Interacts With:    tests/student/test_output_guardrail.py, tests/student/test_audit.py,
                    tests/security/interaction.py, tests/security/trace.py,
                    tests/security/student_guard.py, src/worker/use_cases.py, src/api/routes.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Mutation testing, tests that can fail, evidence from executed runs
Tools:             Python 3.12, ast, pytest (as a subprocess)

A test proves something only if it can fail. This module first runs each student file once
as written, with the harness recording every action each test takes
(``tests/security/trace.py``): that run is the **inventory** of executed cases, one per
collected pytest case. In ``test_output_guardrail.py`` a case counts as the test for one
response when it ran the worker with that response and no other; three such cases are
required, one per supplied response. In ``test_audit.py`` a case counts as an interaction
case when it ran the worker and then read its exception as ``dispatcher-valid`` with a
stored outcome; two such cases are required (the trail test and the credential test). A
name in the source, a constant, or a comment counts for nothing; only what a test did does.

Then it copies ``src/`` to a temporary directory, beside every top-level directory the
copied code reads relative to itself at runtime (``schemas/``, which the guardrail reads,
and ``config/``; ``runtime_directories`` finds them in the source), changes one thing in
the copy, runs the file against it (``PYTHONPATH`` puts the copy first), and judges the
junit outcomes. The two supplied mutations:

| Mutation | Change in the copy | Must fail |
|---|---|---|
| validation-bypass | the raw answer skips the guardrail, to COMPLETED | every bad-answer case |
| header-leak | the request headers join the summary-read event | one interaction case |

The bypass accepts the provider's text as the summary, so the rejection path never runs;
the leak carries the ``Authorization`` header with the ``dispatcher-valid`` bearer token
into the audit record, which the credential test must notice.

Only an assertion failure counts as evidence. A case that ``passed`` or was ``skipped``
did not notice the change; a case that ``errored`` never reached its assertion and makes
the run invalid, which is reported by name; and a failure whose exception is anything but
``AssertionError`` (read from the junit failure's ``type`` or ``message``: a missing file,
a module that cannot be imported, an ``AttributeError`` or ``TypeError`` raised inside the
mutated copy, a ``pytest.raises`` that did not raise) is an invalid run too, never a
detection, because a mutated copy that raised would otherwise make a test that asserts
nothing look like one that noticed the mutation. For ``header-leak`` the runner also
reads what the harness recorded after each request (``tests/security/harness.py``,
``kind: audit``) and credits a failing case only when its read left a ``summary_read``
whose details hold the bearer token: a failure for any other reason is not evidence of
the leak. pytest's exit code is kept and validated: an interrupted (a collection error
included), internal, or usage failure is a tooling error, not a verdict. Cases are keyed
by their full pytest node id on both sides, so two same-named methods in two classes stay
two cases.

Before any of these runs, the student file passes ``tests/security/student_guard.py``. A
file the guard rejects is never executed here: ``MutationError`` names the findings instead.
Source files are read as UTF-8 with an optional BOM (``utf-8-sig``) and the copy is written
back without one. The mutations are applied to the temporary copies only; the student's
files are never changed.

``python -m tests.security.guardrail_mutation`` (``poe guardrail-mutation``) prints both
inventories and the outcome of both mutations; ``tests/contract/test_negative_tests.py``
asserts the same verdicts, one per Check-list row.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from adapters.model.deterministic import RESPONSES
from tests.security import student_guard, trace

TASK_ROOT = Path(__file__).resolve().parents[2]
GUARDRAIL_TEST = Path("tests/student/test_output_guardrail.py")
AUDIT_TEST = Path("tests/student/test_audit.py")
USE_CASES = Path("src/worker/use_cases.py")
ROUTES = Path("src/api/routes.py")
ROUTE_FUNCTION = "get_exception"
GUARDRAIL_CALL = "validate_summary"
BYPASS_NAME = "_bypass_validation"
RECORD_CALL = "record"
SUMMARY_READ_CONSTANT = "summary_read"
SUMMARY_READ_MEMBER = "SUMMARY_READ"
# The parameter the header transform adds when the route has no usable `Request`
# parameter: this name when nothing in the function uses it, otherwise the first
# `leaked_request`, `leaked_request_2`, ... that nothing in the function uses.
REQUEST_PARAMETER = "request"
FALLBACK_REQUEST_PARAMETER = "leaked_request"
REQUEST_ANNOTATION = "Request"
REQUEST_MODULE = "fastapi"
ALLOWED_FIXTURE = "dispatcher-valid"
BAD_RESPONSES: tuple[str, ...] = tuple(name for name in RESPONSES if name != "valid")
MUTATIONS: tuple[str, ...] = ("validation-bypass", "header-leak")
PYTEST_TIMEOUT_SECONDS = 300
# pytest's exit codes that are verdicts: 0 all passed, 1 some failed, 5 nothing collected.
# 2 (interrupted, a collection error included), 3 (internal error), and 4 (usage error) are
# not: the run did not happen as asked.
PYTEST_VERDICT_EXITS = frozenset({0, 1, 5})
# The directory the mutated copy of `src/` is made from, and the directories the copied
# code reads relative to its own location at runtime (`Path(__file__).resolve().parents[2]
# / "<directory>/..."`): the guardrail's schema, the composition root's auth settings.
# Every such directory is copied beside the mutated `src/`, so the copy never raises an
# infrastructure exception for a file the real tree has. `runtime_directories` reads the
# list from the source itself; these two are the ones the shipped tree names.
SOURCE_DIRECTORY = "src"
KNOWN_RUNTIME_DIRECTORIES: frozenset[str] = frozenset({"schemas", "config"})
_RUNTIME_DIRECTORY = re.compile(
    r"Path\(__file__\)\.resolve\(\)\.parents\[2\]\s*/\s*[\"']([A-Za-z0-9_.-]+)[/\"']"
)
# The one exception a failing case may have raised to count as evidence: pytest's rewritten
# `assert`, or an `AssertionError` raised outright. Every other exception is an invalid run.
ASSERTION_EXCEPTION = "AssertionError"
_EXCEPTION_MESSAGE = re.compile(r"^([A-Za-z_][\w.]*)(?::|$)")
_EXCEPTION_LOCATION = re.compile(r":\d+:\s+([A-Za-z_][\w.]*)\s*$")
Transform = Callable[[str], tuple[str, int]]
Requirement = Literal["all", "any"]


class MutationError(RuntimeError):
    """Report that a mutation could not be applied or run, as opposed to a test verdict."""


# --- The transforms ----------------------------------------------------------------------


def _callee(func: ast.expr) -> str | None:
    """Return the simple name a call targets, if it has one."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


_BYPASS_SOURCE = f"""
from worker.guardrail import ValidatedSummary as _BypassValidatedSummary


def {BYPASS_NAME}(raw, *arguments, **keywords):
    return _BypassValidatedSummary(
        summary=raw,
        handling_class="thermal_excursion",
        next_step="operational_review",
        procedure_id=None,
        response_id="0000000000000000",
    )
"""


def bypass_validation(source: str) -> tuple[str, int]:
    """Replace every ``validate_summary(...)`` call with one that accepts the raw answer whole.

    The injected function returns a ``ValidatedSummary`` whose summary is the raw text it was
    handed, so whatever path the student built for an accepted answer runs with the
    provider's text, and the rejection path never runs. Returns the mutated source and how
    many calls were replaced; zero means the module calls the guardrail nowhere.
    """
    tree = ast.parse(source)
    replaced = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _callee(node.func) == GUARDRAIL_CALL:
            node.func = ast.Name(id=BYPASS_NAME, ctx=ast.Load())
            replaced += 1
    if replaced == 0:
        return source, 0
    insert_at = _import_position(tree)
    tree.body[insert_at:insert_at] = ast.parse(_BYPASS_SOURCE).body
    return ast.unparse(ast.fix_missing_locations(tree)), replaced


def _route(tree: ast.Module) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return the ``get_exception`` function definition, wherever it is nested."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == ROUTE_FUNCTION:
            return node
    return None


def _names_summary_read(node: ast.AST) -> bool:
    """Return whether an expression names the summary-read event, by constant or by member."""
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and child.value == SUMMARY_READ_CONSTANT:
            return True
        if isinstance(child, ast.Attribute) and child.attr == SUMMARY_READ_MEMBER:
            return True
        if isinstance(child, ast.Name) and child.id == SUMMARY_READ_MEMBER:
            return True
    return False


def _summary_read_calls(route: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    """Return every ``<sink>.record(...)`` call in the route whose event is the summary read."""
    calls: list[ast.Call] = []
    for node in ast.walk(route):
        if not (isinstance(node, ast.Call) and _callee(node.func) == RECORD_CALL):
            continue
        event = node.args[0] if node.args else None
        if event is None:
            for keyword in node.keywords:
                if keyword.arg == "event":
                    event = keyword.value
        if event is not None and _names_summary_read(event):
            calls.append(node)
    return calls


def _names_in(function: ast.AST) -> set[str]:
    """Return every name a function's body spells: variables, parameters, definitions, aliases."""
    names: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name.split(".", 1)[0])
        elif isinstance(node, ast.ExceptHandler) and node.name is not None:
            names.add(node.name)
        elif isinstance(node, ast.Global | ast.Nonlocal):
            names.update(node.names)
        elif isinstance(node, ast.MatchAs | ast.MatchStar) and node.name is not None:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest is not None:
            names.add(node.rest)
    return names


def _rebound_in(function: ast.AST) -> set[str]:
    """Return every name a function's body binds other than through its own signature.

    A parameter of the function that one of these rebinds (``request = ...`` inside the
    body) does not hold the injected value where the leak reads it.
    """
    bound: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            bound.add(node.id)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            bound.add(node.name)
        elif isinstance(node, ast.alias):
            bound.add(node.asname or node.name.split(".", 1)[0])
        elif isinstance(node, ast.ExceptHandler) and node.name is not None:
            bound.add(node.name)
        elif isinstance(node, ast.Global | ast.Nonlocal):
            bound.update(node.names)
        elif isinstance(node, ast.MatchAs | ast.MatchStar) and node.name is not None:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest is not None:
            bound.add(node.rest)
    for node in ast.walk(function):
        if isinstance(node, ast.Lambda | ast.FunctionDef | ast.AsyncFunctionDef) and (
            node is not function
        ):
            bound.update(argument.arg for argument in _all_arguments(node.args))
    return bound


def _all_arguments(arguments: ast.arguments) -> list[ast.arg]:
    """Return every parameter of a signature, ``*args`` and ``**kwargs`` included."""
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    if arguments.vararg is not None:
        parameters.append(arguments.vararg)
    if arguments.kwarg is not None:
        parameters.append(arguments.kwarg)
    return parameters


def free_parameter_name(route: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Return a parameter name nothing in the route spells: ``request`` or a fallback."""
    taken = _names_in(route)
    if REQUEST_PARAMETER not in taken:
        return REQUEST_PARAMETER
    candidate = FALLBACK_REQUEST_PARAMETER
    counter = 2
    while candidate in taken:
        candidate = f"{FALLBACK_REQUEST_PARAMETER}_{counter}"
        counter += 1
    return candidate


def _request_parameter(route: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, bool]:
    """Return the name of the route's usable ``Request`` parameter, adding one when it has none.

    An existing ``Request``-annotated parameter is reused when nothing in the body
    rebinds its name. FastAPI injects one ``Request`` parameter per route, so a rebound one
    is renamed to a name nothing in the function spells and its old name is assigned from
    it as the body's first statement. Without one, a parameter is added under such a name,
    so no local assignment can overwrite the request before the leak reads it. The flag
    says whether a parameter was added, so the caller can import the annotation.
    """
    rebound = _rebound_in(route)
    for argument in _all_arguments(route.args):
        annotation = argument.annotation
        is_request = (isinstance(annotation, ast.Name) and annotation.id == REQUEST_ANNOTATION) or (
            isinstance(annotation, ast.Attribute) and annotation.attr == REQUEST_ANNOTATION
        )
        if not is_request:
            continue
        if argument.arg not in rebound:
            return argument.arg, False
        original = argument.arg
        name = free_parameter_name(route)
        argument.arg = name
        alias = ast.Assign(
            targets=[ast.Name(id=original, ctx=ast.Store())],
            value=ast.Name(id=name, ctx=ast.Load()),
        )
        route.body.insert(_first_statement(route), alias)
        return name, False
    name = free_parameter_name(route)
    annotation = ast.Name(id=REQUEST_ANNOTATION, ctx=ast.Load())
    parameter = ast.arg(arg=name, annotation=annotation)
    # First, so the defaults of the parameters after it stay aligned with them.
    route.args.args.insert(0, parameter)
    return name, True


def _first_statement(route: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Return the body index after the route's docstring, if it has one."""
    first = route.body[0] if route.body else None
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        return 1
    return 0


def _binds_annotation(tree: ast.Module) -> bool:
    """Return whether the module already imports ``Request`` under that name at top level."""
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if (alias.asname or alias.name) == REQUEST_ANNOTATION:
                    return True
    return False


def _import_position(tree: ast.Module) -> int:
    """Return where an injected import or definition goes: after the imports, past a docstring."""
    insert_at = 0
    for index, statement in enumerate(tree.body):
        if isinstance(statement, ast.Import | ast.ImportFrom):
            insert_at = index + 1
        elif index == 0 and isinstance(statement, ast.Expr):
            insert_at = 1
    return insert_at


def leak_request_headers(source: str) -> tuple[str, int]:
    """Add the request's headers to every summary-read event ``get_exception`` records.

    The route gains a ``Request`` parameter when it has none (FastAPI injects it by
    annotation, wherever it sits; the annotation's import is added when the module lacks
    the name), and each summary-read ``record`` call's ``details`` become the student's
    details plus ``"headers": dict(request.headers)``, which carries the ``Authorization``
    header and the bearer token into the audit record. Returns the mutated source and how
    many calls were changed; zero means the route records no summary read.
    """
    tree = ast.parse(source)
    route = _route(tree)
    if route is None:
        return source, 0
    calls = _summary_read_calls(route)
    if not calls:
        return source, 0
    request_name, added = _request_parameter(route)
    if added and not _binds_annotation(tree):
        imported = ast.ImportFrom(
            module=REQUEST_MODULE, names=[ast.alias(name=REQUEST_ANNOTATION)], level=0
        )
        tree.body.insert(_import_position(tree), imported)
    headers = ast.parse(f"dict({request_name}.headers)", mode="eval").body
    for call in calls:
        existing = next((keyword for keyword in call.keywords if keyword.arg == "details"), None)
        leaked = ast.Dict(keys=[ast.Constant("headers")], values=[headers])
        if existing is None:
            call.keywords.append(ast.keyword(arg="details", value=leaked))
            continue
        leaked.keys.insert(0, None)
        leaked.values.insert(0, existing.value)
        existing.value = leaked
    return ast.unparse(ast.fix_missing_locations(tree)), len(calls)


@dataclass(frozen=True)
class Mutation:
    """One mutation: the student file it targets, the rewrites, and what must fail."""

    name: str
    student_file: Path
    rewrites: tuple[tuple[str, Transform], ...]
    probe_module: str
    requirement: Requirement
    side: str


MUTATION_TABLE: dict[str, Mutation] = {
    "validation-bypass": Mutation(
        name="validation-bypass",
        student_file=GUARDRAIL_TEST,
        rewrites=(("worker/use_cases.py", bypass_validation),),
        probe_module="worker.use_cases",
        requirement="all",
        side="bad-answer cases",
    ),
    "header-leak": Mutation(
        name="header-leak",
        student_file=AUDIT_TEST,
        rewrites=(("api/routes.py", leak_request_headers),),
        probe_module="api.routes",
        requirement="any",
        side="interaction cases",
    ),
}


def apply_mutation(name: str, source_root: Path) -> None:
    """Rewrite the files of one mutation under the temporary ``src`` copy, or raise."""
    mutation = MUTATION_TABLE.get(name)
    if mutation is None:
        raise MutationError(f"unknown mutation {name!r}; choose one of {', '.join(MUTATIONS)}")
    for relative, transform in mutation.rewrites:
        path = source_root / relative
        # `utf-8-sig` drops a leading BOM, which `ast.parse` rejects in an already-decoded
        # string; the copy is written back without one.
        mutated, count = transform(path.read_text(encoding="utf-8-sig"))
        if count == 0:
            if name == "validation-bypass":
                raise MutationError(
                    f"nothing to bypass: {USE_CASES.as_posix()} calls `{GUARDRAIL_CALL}(...)` "
                    "nowhere"
                )
            raise MutationError(
                f"nothing to leak: `{ROUTE_FUNCTION}` in {ROUTES.as_posix()} records no "
                "summary-read event"
            )
        path.write_text(mutated, encoding="utf-8")


# --- The inventory: what each collected test actually did ----------------------------------


@dataclass(frozen=True)
class ExecutedCase:
    """Describe one collected pytest case by what it did through the harness.

    ``name`` is the case's full node id, the identity the trace and the junit report share;
    ``responses`` are the emulator responses it ran the worker with; ``reads`` counts the
    requests it made as ``dispatcher-valid`` for an exception with a stored outcome.
    """

    name: str
    responses: frozenset[str]
    reads: int
    outcome: str
    actions: tuple[str, ...] = ()

    @property
    def dedicated_response(self) -> str | None:
        """Return the one response this case ran the worker with, if exactly one."""
        if len(self.responses) == 1:
            return next(iter(self.responses))
        return None

    @property
    def interaction(self) -> bool:
        """Return whether the case ran the worker and read a stored outcome as the dispatcher."""
        return bool(self.responses) and self.reads > 0


@dataclass(frozen=True)
class Inventory:
    """Hold the executed cases of one run of one student file as written."""

    student_file: Path
    cases: dict[str, ExecutedCase]

    @classmethod
    def from_run(
        cls, student_file: Path, outcomes: dict[str, str], events: list[dict[str, object]]
    ) -> Inventory:
        """Join junit outcomes with the harness's recorded actions, per full case id."""
        responses: dict[str, set[str]] = {name: set() for name in outcomes}
        reads: dict[str, int] = dict.fromkeys(outcomes, 0)
        actions: dict[str, list[str]] = {name: [] for name in outcomes}
        for event in events:
            case = event.get("case")
            if not isinstance(case, str) or case not in outcomes:
                continue
            kind = event.get("kind")
            if kind == "worker":
                response = event.get("response")
                if isinstance(response, str):
                    responses[case].add(response)
                actions[case].append(f"ran the worker with {response!r}")
            elif kind == "read":
                fixture = event.get("fixture")
                path = str(event.get("path", ""))
                stored = bool(event.get("stored_outcome"))
                label = f"{event.get('method', 'GET')} {path} as {fixture or 'no token'}"
                actions[case].append(label if stored else f"{label} (no stored outcome)")
                if (
                    fixture == ALLOWED_FIXTURE
                    and event.get("method", "GET") == "GET"
                    and trace.exception_id_of(path) is not None
                    and stored
                ):
                    reads[case] += 1
        return cls(
            student_file,
            {
                name: ExecutedCase(
                    name, frozenset(responses[name]), reads[name], outcome, tuple(actions[name])
                )
                for name, outcome in outcomes.items()
            },
        )

    def for_response(self, response: str) -> list[str]:
        """Return the cases that ran the worker with ``response`` and no other response."""
        return sorted(
            name for name, case in self.cases.items() if case.dedicated_response == response
        )

    @property
    def bad_answer_cases(self) -> set[str]:
        """Return the cases dedicated to a bad response: what validation-bypass must make fail."""
        return {name for response in BAD_RESPONSES for name in self.for_response(response)}

    @property
    def interaction_cases(self) -> set[str]:
        """Return the cases that ran an interaction and read it: what header-leak judges."""
        return {name for name, case in self.cases.items() if case.interaction}

    def problems(self) -> list[str]:
        """Return everything this file lacks for its required executed cases."""
        if not self.cases:
            return [
                f"{self.student_file.as_posix()} ran no test; write the tests the template marks"
            ]
        if self.student_file == GUARDRAIL_TEST:
            missing = [response for response in RESPONSES if not self.for_response(response)]
            if not missing:
                return []
            return [
                "no test ran the worker with "
                + ", ".join(f"'{response}'" for response in missing)
                + " alone: write one guardrail test per supplied response"
            ]
        count = len(self.interaction_cases)
        if count >= 2:
            return []
        return [
            f"{count} test(s) ran the worker and then read the exception as "
            f"'{ALLOWED_FIXTURE}' with a stored outcome; two are required: the ordered-trail "
            "test and the credential test"
        ]

    def describe(self) -> str:
        """Render the inventory as a Markdown table, for `poe guardrail-mutation` and messages."""
        lines = ["| Case | Did | Outcome |", "|---|---|---|"]
        for name in sorted(self.cases):
            case = self.cases[name]
            did = "; ".join(case.actions) or "-"
            lines.append(f"| `{name}` | {did} | {case.outcome} |")
        return "\n".join(lines)


@dataclass(frozen=True)
class RunResult:
    """What one run of a student file reported, per junit test case.

    ``leaked_reads`` are the cases whose requests, as the harness recorded them after the
    response, left a ``summary_read`` whose details hold the bearer token the request
    sent: under ``header-leak`` only such a case can be credited with noticing the leak.
    """

    mutation: str
    outcomes: dict[str, str]
    returncode: int = 1
    leaked_reads: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Verdict:
    """Whether one mutation made the required cases fail, and why not."""

    mutation: str
    required: set[str]
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Return whether the mutation is proven by the student's tests."""
        return not self.problems


# --- Running a student file ----------------------------------------------------------------


def failure_exception(failure: ET.Element) -> str:
    """Return the name of the exception a junit failure reports, or ``""`` when it says none.

    Read in this order: the element's ``type`` attribute when a writer sets one; the
    ``message`` attribute, which pytest fills with the exception line (``<Name>: <text>``,
    or the bare ``assert ...`` line for a rewritten assertion, whose ``AssertionError: ``
    prefix pytest strips); and the last line of the failure text, which pytest's long
    traceback ends with ``<path>:<line>: <Name>``. A dotted name is reduced to its last
    component.
    """
    declared = failure.attrib.get("type", "").strip()
    if declared:
        return declared.rsplit(".", 1)[-1]
    message = failure.attrib.get("message", "").strip()
    if message.startswith("assert") and (len(message) == 6 or not message[6].isalnum()):
        return ASSERTION_EXCEPTION
    matched = _EXCEPTION_MESSAGE.match(message)
    if matched:
        return matched.group(1).rsplit(".", 1)[-1]
    text = (failure.text or "").strip()
    if text:
        located = _EXCEPTION_LOCATION.search(text.splitlines()[-1])
        if located:
            return located.group(1).rsplit(".", 1)[-1]
    return ""


def _parse_junit(report: Path) -> dict[str, str]:
    """Return each junit test case's outcome, keyed by its full case id.

    The key is ``trace.junit_case_id(classname, name)``, the same identity the trace
    records, so a method name shared by two classes and the parameters of one function
    stay distinct. Two test cases with one identity make the report unusable: the later
    one would silently overwrite the earlier, so the run is rejected instead. A failure
    is ``failed`` only when its exception is ``AssertionError``; any other exception, or
    one the report does not name, is recorded as an ``error`` with the exception's name
    after a colon (``error:AttributeError``, ``error:unknown``), never as a failure.
    """
    outcomes: dict[str, str] = {}
    if not report.is_file():
        return outcomes
    for case in ET.parse(report).iter("testcase"):
        identity = trace.junit_case_id(
            case.attrib.get("classname", ""), case.attrib.get("name", "")
        )
        if identity in outcomes:
            raise MutationError(
                f"the junit report names {identity} twice; one outcome per collected case is "
                "required"
            )
        failure = case.find("failure")
        if case.find("error") is not None:
            outcomes[identity] = "error"
        elif failure is not None:
            exception = failure_exception(failure)
            if exception == ASSERTION_EXCEPTION:
                outcomes[identity] = "failed"
            else:
                outcomes[identity] = f"error:{exception or 'unknown'}"
        elif case.find("skipped") is not None:
            outcomes[identity] = "skipped"
        else:
            outcomes[identity] = "passed"
    return outcomes


def runtime_directories(root: Path = TASK_ROOT) -> set[str]:
    """Return the top-level directories the code under ``src/`` reads relative to itself.

    Found in the source: every ``Path(__file__).resolve().parents[2] / "<directory>/..."``
    expression names one. The mutation workspace copies each of them beside the mutated
    ``src/``, so a copied module finds the same files the real one does.
    """
    found: set[str] = set()
    for path in sorted((root / SOURCE_DIRECTORY).rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for match in _RUNTIME_DIRECTORY.finditer(path.read_text(encoding="utf-8-sig")):
            found.add(match.group(1))
    return found


def build_workspace(root: Path, workspace: Path) -> Path:
    """Copy ``src/`` and every runtime directory under ``workspace``; return the copied ``src``.

    The copy is complete by construction: ``runtime_directories`` names what the source
    reads relative to itself, and the shipped tree's known directories are copied even if
    a rewrite of the source stopped naming them, so a mutated run never raises an
    infrastructure exception the real tree would not.
    """
    ignored = shutil.ignore_patterns("__pycache__", "*.pyc")
    source_root = workspace / SOURCE_DIRECTORY
    shutil.copytree(root / SOURCE_DIRECTORY, source_root, ignore=ignored)
    for directory in sorted(runtime_directories(root) | KNOWN_RUNTIME_DIRECTORIES):
        if (root / directory).is_dir():
            shutil.copytree(root / directory, workspace / directory, ignore=ignored)
    return source_root


def guard_student_file(student_file: Path, root: Path = TASK_ROOT) -> None:
    """Refuse to execute a student file the static guard rejects, naming every finding.

    Every execution of a file in this module goes through here first: the inventory run
    and each mutated run. The guard parses the file's bytes and never imports it.
    """
    try:
        found = student_guard.findings(root / student_file)
    except student_guard.StudentGuardError as exc:
        raise MutationError(str(exc)) from exc
    if found:
        raise MutationError(
            f"{student_file.as_posix()} was not run: it must use only the supplied harness "
            "and assert each outcome (`poe student-guard`):\n- " + "\n- ".join(found)
        )


def _run_student_file(
    root: Path, student_file: Path, mutation: Mutation | None
) -> tuple[RunResult, list[dict[str, object]]]:
    """Run one student file once, as written or against one mutated copy of ``src``.

    The static guard runs first and the file is not executed when it has findings. The
    run records every action made through the harness. Under a mutation the workspace
    (``src/`` beside the directories it reads at runtime) is built in a temporary
    directory, the copy is put first on ``PYTHONPATH`` for the pytest subprocess, and the
    subprocess is asked where it imports the mutated module from before the tests run, so
    a run against the unmutated code can never pass as a mutated one. pytest's exit code
    is validated: only a verdict exit (all passed, some failed, nothing collected) is
    accepted, and a verdict exit must come with a junit report.
    """
    guard_student_file(student_file, root)
    label = mutation.name if mutation is not None else "as written"
    with tempfile.TemporaryDirectory(prefix="coldline-mutation-") as temporary:
        environment = os.environ.copy()
        if mutation is not None:
            source_root = build_workspace(root, Path(temporary))
            apply_mutation(mutation.name, source_root)
            existing = environment.get("PYTHONPATH")
            environment["PYTHONPATH"] = (
                str(source_root) if not existing else os.pathsep.join([str(source_root), existing])
            )
            module = mutation.probe_module
            probe = subprocess.run(
                [sys.executable, "-c", f"import {module}; print({module}.__file__)"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            imported = (
                Path(probe.stdout.strip()) if probe.returncode == 0 and probe.stdout else None
            )
            if imported is None or not imported.resolve().is_relative_to(source_root.resolve()):
                raise MutationError(
                    "the mutated copy was not the one imported: "
                    f"{probe.stdout.strip() or probe.stderr.strip()}"
                )
        report = Path(temporary) / "report.xml"
        recorded = Path(temporary) / "trace.jsonl"
        environment[trace.TRACE_VARIABLE] = str(recorded)
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(root / student_file),
                "-q",
                "-p",
                "no:cacheprovider",
                f"--junitxml={report}",
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=PYTEST_TIMEOUT_SECONDS,
        )
        if completed.returncode not in PYTEST_VERDICT_EXITS:
            tail = (completed.stdout + completed.stderr).strip().splitlines()[-12:]
            raise MutationError(
                f"pytest exited {completed.returncode} running {student_file.as_posix()} "
                f"{label}, which is not a verdict (collection, usage, or internal error):\n"
                + "\n".join(tail)
            )
        if completed.returncode != 5 and not report.is_file():
            raise MutationError(
                f"pytest exited {completed.returncode} running {student_file.as_posix()} "
                f"{label} but wrote no junit report"
            )
        outcomes = _parse_junit(report)
        return RunResult(label, outcomes, completed.returncode), trace.read_events(recorded)


_INVENTORIES: dict[tuple[Path, Path, str], Inventory] = {}


def collect_inventory(
    student_file: Path, root: Path = TASK_ROOT, *, refresh: bool = False
) -> Inventory:
    """Run one student file as written and return what each collected case did.

    The result is kept per process for the file's current content, so the assessed rows
    that share one pytest process run each inventory once.
    """
    path = root / student_file
    if not path.is_file():
        raise MutationError(f"{student_file.as_posix()} does not exist")
    content = path.read_bytes()
    try:
        ast.parse(content)
    except SyntaxError as exc:
        raise MutationError(f"{student_file.as_posix()} is not valid Python: {exc}") from exc
    key = (root.resolve(), student_file, hashlib.sha256(content).hexdigest())
    if refresh or key not in _INVENTORIES:
        result, events = _run_student_file(root, student_file, None)
        _INVENTORIES[key] = Inventory.from_run(student_file, result.outcomes, events)
    return _INVENTORIES[key]


def cases_with_leaked_read(events: list[dict[str, object]]) -> frozenset[str]:
    """Return the cases whose requests left a summary read holding the bearer token they sent.

    Read from the ``kind: audit`` lines the harness records after each response.
    """
    return frozenset(
        str(event["case"])
        for event in events
        if event.get("kind") == "audit"
        and event.get("bearer_in_summary_read") is True
        and isinstance(event.get("case"), str)
    )


def run_mutation(name: str, *, root: Path = TASK_ROOT) -> RunResult:
    """Copy ``src``, apply one mutation, run its student file against the copy, and report."""
    mutation = MUTATION_TABLE.get(name)
    if mutation is None:
        raise MutationError(f"unknown mutation {name!r}; choose one of {', '.join(MUTATIONS)}")
    result, events = _run_student_file(root, mutation.student_file, mutation)
    return replace(result, leaked_reads=cases_with_leaked_read(events))


# --- Judging ------------------------------------------------------------------------------


def required_tests(name: str, inventory: Inventory) -> tuple[set[str], list[str]]:
    """Return the cases one mutation judges, and why that set is not yet complete."""
    problems = inventory.problems()
    if name == "validation-bypass":
        return inventory.bad_answer_cases, problems
    return inventory.interaction_cases, problems


def judge(name: str, inventory: Inventory, result: RunResult) -> Verdict:
    """Decide whether one mutation made the required cases fail on an assertion of their own.

    Only ``failed`` (an ``AssertionError``) counts; under ``header-leak`` a failed case
    counts only when the harness recorded that its read left a summary read holding the
    bearer token, so the failure is about the leaked header and not about something else
    the mutated copy did.
    """
    mutation = MUTATION_TABLE[name]
    required, problems = required_tests(name, inventory)
    if not result.outcomes:
        problems.append(f"{mutation.student_file.as_posix()} produced no test cases under {name}")
    errored = sorted(
        f"{case} ({outcome.split(':', 1)[1]})" if ":" in outcome else case
        for case, outcome in result.outcomes.items()
        if outcome.startswith("error")
    )
    if errored:
        problems.append(
            f"the run under {name} is invalid: {', '.join(errored)} errored; a fixture, "
            "setup, or collection error, or an exception other than AssertionError (a missing "
            "file or module, an AttributeError or TypeError raised by the mutated copy), is "
            "not a failing assertion"
        )
    failed = {case for case in required if result.outcomes.get(case) == "failed"}
    for case in sorted(required):
        outcome = result.outcomes.get(case)
        if outcome is None:
            problems.append(f"{case} produced no test case under {name}")
        elif outcome == "skipped":
            problems.append(f"{case} was skipped under {name}")
        elif outcome == "passed" and mutation.requirement == "all":
            problems.append(f"{case} still passes with {name}")
    if mutation.requirement == "any" and required:
        if not failed:
            problems.append(
                f"every {mutation.side[:-1]} still passes with {name}: none of "
                f"{', '.join(sorted(required))} noticed the leaked headers"
            )
        unproven = sorted(failed - result.leaked_reads)
        if unproven and not (failed & result.leaked_reads):
            problems.append(
                f"{', '.join(unproven)} failed under {name}, but the mutated route recorded no "
                "summary read carrying the bearer header for the exception each one read; the "
                "failure is not evidence of the leak"
            )
    return Verdict(name, required, problems)


def check(name: str, *, root: Path = TASK_ROOT) -> Verdict:
    """Collect the inventory, then run one mutation against its student file and judge it.

    The structural precondition (the cases the mutation judges were executed and did what
    the file requires) is checked first, so a file without them is reported without a
    mutated run.
    """
    mutation = MUTATION_TABLE.get(name)
    if mutation is None:
        raise MutationError(f"unknown mutation {name!r}; choose one of {', '.join(MUTATIONS)}")
    inventory = collect_inventory(mutation.student_file, root)
    required, problems = required_tests(name, inventory)
    if problems:
        return Verdict(name, required, problems)
    return judge(name, inventory, run_mutation(name, root=root))


def main() -> int:
    """Print both inventories, then run both mutations and print what each one proved."""
    exit_code = 0
    for student_file in (GUARDRAIL_TEST, AUDIT_TEST):
        print(f"## executed cases: {student_file.as_posix()}\n")
        try:
            inventory = collect_inventory(student_file)
        except MutationError as exc:
            print(f"not run: {exc}\n")
            exit_code = 1
            continue
        print(inventory.describe())
        print()
        for problem in inventory.problems():
            exit_code = 1
            print(f"- {problem}")
        if inventory.problems():
            print()
    for name in MUTATIONS:
        mutation = MUTATION_TABLE[name]
        try:
            verdict = check(name)
        except MutationError as exc:
            print(f"## {name}\n\nnot run: {exc}\n")
            exit_code = 1
            continue
        print(f"## {name}\n")
        rule = "every case must fail" if mutation.requirement == "all" else "one case must fail"
        judged = ", ".join(sorted(verdict.required)) or "(none found)"
        print(f"judged: {judged} ({mutation.side}; {rule})")
        if verdict.ok:
            print("verdict: proven\n")
        else:
            exit_code = 1
            print("verdict: NOT proven")
            for problem in verdict.problems:
                print(f"- {problem}")
            print()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
