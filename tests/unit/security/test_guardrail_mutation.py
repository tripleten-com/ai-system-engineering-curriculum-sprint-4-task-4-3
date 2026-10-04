"""Coldline.

===================

File:              tests/unit/security/test_guardrail_mutation.py
Component:         Unit tests — Guardrail and audit mutations
Purpose:           Prove the two transforms, the mutation workspace, the executed-case
                    inventories, and the judge without a stack.
Interacts With:    tests/security/guardrail_mutation.py, tests/security/trace.py,
                    src/worker/use_cases.py, src/api/routes.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Mutation testing, AST rewriting, evidence from executed runs, complete
                    workspaces, only assertion failures as evidence
Tools:             Python 3.12, pytest, httpx, FastAPI

The snippets the transforms are fed are probes, the smallest modules that exercise the
tooling path under test: a function that hands a text to `validate_summary`, and a route
that records one summary read with a placeholder field. They show nothing of the Task's
solution. Most tests spawn no pytest subprocess; the one that does builds a scratch tree
with probe modules in place of the student files and runs the real `check` against it,
so no shipped student file is read here.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import sys
import tomllib
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape, quoteattr

import httpx
import pytest

from common.audit import AuditSink
from tests.security import guardrail_mutation as mutation
from tests.security import trace
from tests.security.harness import MemoryAuditStore
from worker.guardrail import ValidatedSummary

TASK_ROOT = Path(__file__).resolve().parents[3]
GUARDRAIL = mutation.GUARDRAIL_TEST
AUDIT = mutation.AUDIT_TEST

# The worker probe: one call to the guardrail, nothing stored, no policy.
PROBE_WORKER = '''"""Worker probe."""

from worker.guardrail import validate_summary


def check(answer_text):
    verdict = validate_summary(answer_text)
    return verdict
'''

# The route probe: one summary read with one placeholder field, no access rule, no
# eligibility condition. It does not import `Request`, so the transform must add it.
PROBE_ROUTE = '''"""Route probe."""

from fastapi import FastAPI


def create_app(audit):
    app = FastAPI()

    @app.get("/api/v1/exceptions/{exception_id}")
    async def get_exception(exception_id: str) -> dict:
        await audit.record("summary_read", exception_id=exception_id, details={"subject": "probe"})
        return {"exception_id": exception_id}

    return app
'''

ROUTE_WITH_REQUEST = PROBE_ROUTE.replace(
    "from fastapi import FastAPI\n", "from fastapi import FastAPI, Request\n"
).replace(
    "async def get_exception(exception_id: str) -> dict:",
    "async def get_exception(exception_id: str, request: Request) -> dict:",
)
ROUTE_WITHOUT_DETAILS = PROBE_ROUTE.replace(', details={"subject": "probe"}', "")
ROUTE_BY_MEMBER = PROBE_ROUTE.replace(
    "from fastapi import FastAPI\n",
    "from fastapi import FastAPI\n\nfrom common.audit import AuditEvent\n",
).replace('"summary_read"', "AuditEvent.SUMMARY_READ")
STARTER_ROUTE = '''"""Route probe without a read event."""

from fastapi import FastAPI


def create_app(audit):
    app = FastAPI()

    @app.get("/api/v1/exceptions/{exception_id}")
    async def get_exception(exception_id: str) -> dict:
        return {"exception_id": exception_id}

    return app
'''
# The probe's one record call, and the same call with the local `request` as its subject.
RECORD_CALL = (
    '        await audit.record("summary_read", exception_id=exception_id, '
    'details={"subject": "probe"})\n'
)
RECORD_CALL_WITH_LOCAL = RECORD_CALL.replace('"probe"', "request")
# The review's collision: a local variable named `request` inside the route. A transform
# that injected a parameter of that name would see it overwritten before the leak reads it.
ROUTE_WITH_LOCAL_REQUEST = PROBE_ROUTE.replace(
    RECORD_CALL,
    '        request = f"/api/v1/exceptions/{exception_id}"\n' + RECORD_CALL_WITH_LOCAL,
)
# A `Request` parameter that the body rebinds: not usable either.
ROUTE_REBINDING_ITS_REQUEST = ROUTE_WITH_REQUEST.replace(
    RECORD_CALL, "        request = exception_id\n" + RECORD_CALL_WITH_LOCAL
)


# --- The transforms ----------------------------------------------------------------------


def test_bypass_validation_accepts_the_raw_answer_as_the_summary() -> None:
    """The replaced call returns a ValidatedSummary whose summary is the text it was handed."""
    mutated, count = mutation.bypass_validation(PROBE_WORKER)

    assert count == 1
    assert "validate_summary(answer_text)" not in mutated
    assert f"{mutation.BYPASS_NAME}(answer_text)" in mutated
    namespace: dict[str, Any] = {"__name__": "mutated_worker"}
    exec(compile(mutated, "<use_cases.py validation-bypass>", "exec"), namespace)
    verdict = namespace["check"]("not json at all")
    assert isinstance(verdict, ValidatedSummary)
    assert verdict.summary == "not json at all"
    bypass = namespace[mutation.BYPASS_NAME]
    assert isinstance(bypass("x"), ValidatedSummary)
    assert isinstance(bypass(raw="x"), ValidatedSummary)


def test_bypass_validation_leaves_a_module_without_the_call_untouched() -> None:
    """Zero replacements hand the source back byte for byte."""
    source = "def process():\n    return parse_summary(answer)\n"
    assert mutation.bypass_validation(source) == (source, 0)


def test_bypass_validation_keeps_a_future_import_first() -> None:
    """The injected helper lands after the imports, so a `__future__` import stays first."""
    source = (
        '"""Doc."""\n\nfrom __future__ import annotations\n\nfrom worker.guardrail import '
        "validate_summary\n\n\ndef f(raw):\n    return validate_summary(raw)\n"
    )
    mutated, count = mutation.bypass_validation(source)
    assert count == 1
    body = ast.parse(mutated).body
    assert isinstance(body[0], ast.Expr)
    assert isinstance(body[1], ast.ImportFrom) and body[1].module == "__future__"
    names = [node.name for node in body if isinstance(node, ast.FunctionDef)]
    assert names == [mutation.BYPASS_NAME, "f"]


@pytest.mark.parametrize(
    "source", [PROBE_ROUTE, ROUTE_WITH_REQUEST, ROUTE_WITHOUT_DETAILS, ROUTE_BY_MEMBER]
)
@pytest.mark.asyncio
async def test_leak_request_headers_puts_the_authorization_header_in_the_read_event(
    source: str,
) -> None:
    """Whatever the route's shape, the mutated summary read carries the request's headers."""
    mutated, count = mutation.leak_request_headers(source)

    assert count == 1
    assert "dict(request.headers)" in mutated
    namespace: dict[str, Any] = {"__name__": "mutated_routes"}
    exec(compile(mutated, "<routes.py header-leak>", "exec"), namespace)
    store = MemoryAuditStore()
    app = namespace["create_app"](AuditSink(store))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        admitted = await client.get(
            "/api/v1/exceptions/exc-1", headers={"Authorization": "Bearer secret-token"}
        )

    assert admitted.status_code == 200
    [record] = store.records
    assert record.event == "summary_read"
    headers = record.details["headers"]
    assert isinstance(headers, dict)
    assert headers["authorization"] == "Bearer secret-token"
    if source is not ROUTE_WITHOUT_DETAILS:
        assert record.details["subject"] == "probe"
    assert "Bearer secret-token" in record.rendered()


def test_leak_request_headers_imports_the_annotation_it_adds_and_only_then() -> None:
    """A route without `Request` gains its import; one that has it gains no second import."""
    mutated, _ = mutation.leak_request_headers(PROBE_ROUTE)
    imports = [
        node
        for node in ast.parse(mutated).body
        if isinstance(node, ast.ImportFrom) and node.module == mutation.REQUEST_MODULE
    ]
    names = {alias.name for node in imports for alias in node.names}
    assert mutation.REQUEST_ANNOTATION in names
    assert mutated.index("import") < mutated.index("def create_app")

    mutated, _ = mutation.leak_request_headers(ROUTE_WITH_REQUEST)
    assert mutated.count(f"import FastAPI, {mutation.REQUEST_ANNOTATION}") == 1
    assert "from fastapi import Request\n" not in mutated


def test_leak_request_headers_finds_nothing_in_a_route_without_a_read_event() -> None:
    """A route that records no summary read is handed back unchanged with a zero count."""
    assert mutation.leak_request_headers(STARTER_ROUTE) == (STARTER_ROUTE, 0)


@pytest.mark.parametrize(
    "source", [ROUTE_WITH_LOCAL_REQUEST, ROUTE_REBINDING_ITS_REQUEST], ids=["local", "rebound"]
)
@pytest.mark.asyncio
async def test_leak_request_headers_picks_a_parameter_name_the_route_does_not_use(
    source: str,
) -> None:
    """A local `request`, or a rebound `request: Request`, never shadows the injected parameter.

    The transform adds a parameter under a name nothing in the route spells, and the
    mutated route still records the bearer header instead of raising `AttributeError`
    on the local string.
    """
    mutated, count = mutation.leak_request_headers(source)

    assert count == 1
    route = mutation._route(ast.parse(mutated))
    assert route is not None
    names = [argument.arg for argument in route.args.args]
    assert mutation.FALLBACK_REQUEST_PARAMETER in names, names
    assert names.count(mutation.REQUEST_PARAMETER) == 0, names
    assert f"dict({mutation.FALLBACK_REQUEST_PARAMETER}.headers)" in mutated
    namespace: dict[str, Any] = {"__name__": "mutated_routes"}
    exec(compile(mutated, "<routes.py header-leak>", "exec"), namespace)
    store = MemoryAuditStore()
    app = namespace["create_app"](AuditSink(store))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        admitted = await client.get(
            "/api/v1/exceptions/exc-1", headers={"Authorization": "Bearer secret-token"}
        )

    assert admitted.status_code == 200
    [record] = store.records
    assert record.details["headers"]["authorization"] == "Bearer secret-token"


def test_free_parameter_name_skips_every_name_the_route_spells() -> None:
    """`request` when free; otherwise the first `leaked_request[_n]` nothing in the route uses."""
    route = mutation._route(ast.parse(PROBE_ROUTE))
    assert route is not None
    assert mutation.free_parameter_name(route) == "request"

    crowded = ast.parse(
        "async def get_exception(exception_id, leaked_request):\n"
        "    request = 1\n"
        "    leaked_request_2 = lambda leaked_request_3: leaked_request_3\n"
        "    return exception_id\n"
    )
    route = mutation._route(crowded)
    assert route is not None
    assert mutation.free_parameter_name(route) == "leaked_request_4"


def test_apply_mutation_names_what_it_could_not_change(tmp_path: Path) -> None:
    """A copy whose module calls no guardrail, or records no read, is a named tooling error."""
    source_root = tmp_path / "src"
    (source_root / "worker").mkdir(parents=True)
    (source_root / "api").mkdir()
    (source_root / "worker/use_cases.py").write_text("def process():\n    pass\n", encoding="utf-8")
    (source_root / "api/routes.py").write_text(STARTER_ROUTE, encoding="utf-8")

    with pytest.raises(mutation.MutationError, match="nothing to bypass"):
        mutation.apply_mutation("validation-bypass", source_root)
    with pytest.raises(mutation.MutationError, match="nothing to leak"):
        mutation.apply_mutation("header-leak", source_root)
    with pytest.raises(mutation.MutationError, match="unknown mutation"):
        mutation.apply_mutation("rule-removed", source_root)


def test_every_mutation_rewrites_a_shipped_file_and_applies_to_a_bom_bearing_copy(
    tmp_path: Path,
) -> None:
    """Each mutation names a real module; a UTF-8 BOM on the copy does not break the rewrite."""
    assert set(mutation.MUTATION_TABLE) == set(mutation.MUTATIONS)
    for name, entry in mutation.MUTATION_TABLE.items():
        for relative, _ in entry.rewrites:
            assert (TASK_ROOT / "src" / relative).is_file(), (name, relative)
    source_root = tmp_path / "src"
    (source_root / "worker").mkdir(parents=True)
    (source_root / "api").mkdir()
    bom = b"\xef\xbb\xbf"
    (source_root / "worker/use_cases.py").write_bytes(bom + PROBE_WORKER.encode("utf-8"))
    (source_root / "api/routes.py").write_bytes(bom + PROBE_ROUTE.encode("utf-8"))

    mutation.apply_mutation("validation-bypass", source_root)
    mutation.apply_mutation("header-leak", source_root)

    for relative in ("worker/use_cases.py", "api/routes.py"):
        rewritten = (source_root / relative).read_bytes()
        assert not rewritten.startswith(bom), relative
        ast.parse(rewritten)


# --- The workspace -------------------------------------------------------------------------


def test_the_shipped_source_reads_the_schema_and_config_directories_relative_to_itself() -> None:
    """`runtime_directories` finds every `parents[2] / "<dir>/..."` in src/: the schema first."""
    found = mutation.runtime_directories(TASK_ROOT)

    assert mutation.KNOWN_RUNTIME_DIRECTORIES <= found, found
    for directory in found:
        assert (TASK_ROOT / directory).is_dir(), directory


def test_the_workspace_copies_src_beside_every_directory_it_reads(tmp_path: Path) -> None:
    """The copy holds src/, the directories the source names, and the known ones; nothing else."""
    root = tmp_path / "root"
    (root / "src/worker").mkdir(parents=True)
    (root / "src/worker/guardrail.py").write_text(
        "from pathlib import Path\n\n"
        'SCHEMA = Path(__file__).resolve().parents[2] / "rules/a.json"\n',
        encoding="utf-8",
    )
    (root / "src/worker/__pycache__").mkdir()
    (root / "src/worker/__pycache__/guardrail.cpython-312.pyc").write_bytes(b"\x00")
    (root / "rules").mkdir()
    (root / "rules/a.json").write_text("{}\n", encoding="utf-8")
    (root / "schemas").mkdir()
    (root / "schemas/b.json").write_text("{}\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs/note.md").write_text("not copied\n", encoding="utf-8")

    assert mutation.runtime_directories(root) == {"rules"}
    source_root = mutation.build_workspace(root, tmp_path / "workspace")

    assert source_root == tmp_path / "workspace/src"
    assert (source_root / "worker/guardrail.py").is_file()
    assert not (source_root / "worker/__pycache__").exists()
    assert (tmp_path / "workspace/rules/a.json").is_file()
    assert (tmp_path / "workspace/schemas/b.json").is_file()
    assert not (tmp_path / "workspace/config").exists()
    assert not (tmp_path / "workspace/docs").exists()


def test_a_copied_guardrail_finds_its_schema_inside_the_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guardrail copied beside the copied schema resolves and loads the copy's schema."""
    source_root = mutation.build_workspace(TASK_ROOT, tmp_path / "workspace")
    copied = source_root / "worker/guardrail.py"
    assert copied.is_file()
    assert (tmp_path / "workspace/schemas/exception-summary.schema.json").is_file()

    spec = importlib.util.spec_from_file_location("copied_guardrail", copied)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "copied_guardrail", module)
    spec.loader.exec_module(module)

    assert module.SCHEMA_PATH.is_relative_to((tmp_path / "workspace").resolve())
    assert module.SCHEMA_PATH.is_file()
    assert module.load_schema(module.SCHEMA_PATH)["additionalProperties"] is False


# --- The inventories ----------------------------------------------------------------------


def _worker(case: str, response: str) -> dict[str, object]:
    """Return one recorded worker run, as the harness writes it."""
    return {"case": case, "kind": "worker", "response": response, "exception_id": "exc-1"}


def _read(case: str, fixture: str | None, stored: bool = True) -> dict[str, object]:
    """Return one recorded request, as the harness writes it."""
    return {
        "case": case,
        "kind": "read",
        "fixture": fixture,
        "method": "GET",
        "path": f"{trace.SUMMARY_ROUTE}exc-1",
        "exception_id": "exc-1",
        "stored_outcome": stored,
    }


def _guardrail_inventory() -> mutation.Inventory:
    """Return a complete guardrail inventory: one case per response."""
    outcomes = {
        f"{GUARDRAIL.as_posix()}::test_{response}": "passed" for response in mutation.RESPONSES
    }
    events = [_worker(name, name.rsplit("_", 1)[1]) for name in outcomes]
    return mutation.Inventory.from_run(GUARDRAIL, outcomes, events)


def _audit_inventory() -> mutation.Inventory:
    """Return a complete audit inventory: a trail test and a credential test."""
    outcomes = {
        f"{AUDIT.as_posix()}::test_trail": "passed",
        f"{AUDIT.as_posix()}::test_credential": "passed",
    }
    events = [
        _worker(f"{AUDIT.as_posix()}::test_trail", "manipulated"),
        _read(f"{AUDIT.as_posix()}::test_trail", "dispatcher-valid"),
        _worker(f"{AUDIT.as_posix()}::test_credential", "valid"),
        _read(f"{AUDIT.as_posix()}::test_credential", "dispatcher-valid"),
    ]
    return mutation.Inventory.from_run(AUDIT, outcomes, events)


def test_the_guardrail_inventory_requires_one_dedicated_case_per_response() -> None:
    """Three cases, each running the worker with one response alone, satisfy the file."""
    inventory = _guardrail_inventory()

    assert inventory.problems() == []
    for response in mutation.RESPONSES:
        assert inventory.for_response(response) == [f"{GUARDRAIL.as_posix()}::test_{response}"]
    assert inventory.bad_answer_cases == {
        f"{GUARDRAIL.as_posix()}::test_malformed",
        f"{GUARDRAIL.as_posix()}::test_manipulated",
    }

    mixed = mutation.Inventory.from_run(
        GUARDRAIL,
        {"test_both": "passed", "test_valid": "passed"},
        [
            _worker("test_both", "malformed"),
            _worker("test_both", "manipulated"),
            _worker("test_valid", "valid"),
        ],
    )
    assert mixed.for_response("malformed") == []
    assert mixed.problems() == [
        "no test ran the worker with 'malformed', 'manipulated' alone: write one guardrail "
        "test per supplied response"
    ]
    assert mutation.Inventory.from_run(GUARDRAIL, {}, []).problems() == [
        "tests/student/test_output_guardrail.py ran no test; write the tests the template marks"
    ]


def test_the_audit_inventory_requires_two_interaction_cases() -> None:
    """A case counts when it ran the worker and read its exception as the dispatcher."""
    inventory = _audit_inventory()

    assert inventory.problems() == []
    assert inventory.interaction_cases == {
        f"{AUDIT.as_posix()}::test_trail",
        f"{AUDIT.as_posix()}::test_credential",
    }

    partial = mutation.Inventory.from_run(
        AUDIT,
        {"test_no_read": "passed", "test_wrong_fixture": "passed", "test_unstored": "passed"},
        [
            _worker("test_no_read", "valid"),
            _worker("test_wrong_fixture", "valid"),
            _read("test_wrong_fixture", "expired"),
            _worker("test_unstored", "valid"),
            _read("test_unstored", "dispatcher-valid", stored=False),
        ],
    )
    assert partial.interaction_cases == set()
    [problem] = partial.problems()
    assert problem.startswith("0 test(s) ran the worker and then read the exception")
    assert "(no stored outcome)" in partial.cases["test_unstored"].actions[1]


def test_the_inventory_renders_as_a_table() -> None:
    """`poe guardrail-mutation` prints what each case did, for the student to read."""
    table = _audit_inventory().describe()

    assert table.splitlines()[0] == "| Case | Did | Outcome |"
    assert "ran the worker with 'manipulated'; GET /api/v1/exceptions/exc-1 as" in table


# --- The judge ----------------------------------------------------------------------------


def test_bypass_requires_every_bad_answer_case_to_fail_and_counts_only_failed() -> None:
    """Under validation-bypass both bad-answer cases must fail; the valid case is not judged."""
    inventory = _guardrail_inventory()
    valid, malformed, manipulated = (
        f"{GUARDRAIL.as_posix()}::test_{response}" for response in mutation.RESPONSES
    )

    proven = mutation.judge(
        "validation-bypass",
        inventory,
        mutation.RunResult(
            "validation-bypass", {valid: "passed", malformed: "failed", manipulated: "failed"}
        ),
    )
    assert proven.ok and proven.required == {malformed, manipulated}

    weak = mutation.judge(
        "validation-bypass",
        inventory,
        mutation.RunResult(
            "validation-bypass", {valid: "failed", malformed: "passed", manipulated: "skipped"}
        ),
    )
    assert weak.problems == [
        f"{malformed} still passes with validation-bypass",
        f"{manipulated} was skipped under validation-bypass",
    ]

    errored = mutation.judge(
        "validation-bypass",
        inventory,
        mutation.RunResult("validation-bypass", {malformed: "error", manipulated: "failed"}),
    )
    assert not errored.ok
    [problem] = errored.problems
    assert problem.startswith(f"the run under validation-bypass is invalid: {malformed} errored")
    assert "is not a failing assertion" in problem


def test_header_leak_requires_at_least_one_interaction_case_to_fail_on_a_leaked_read() -> None:
    """Under header-leak the credential test fails after a leaked read; the trail test may pass."""
    inventory = _audit_inventory()
    trail, credential = f"{AUDIT.as_posix()}::test_trail", f"{AUDIT.as_posix()}::test_credential"

    proven = mutation.judge(
        "header-leak",
        inventory,
        mutation.RunResult(
            "header-leak",
            {trail: "passed", credential: "failed"},
            leaked_reads=frozenset({trail, credential}),
        ),
    )
    assert proven.ok

    unnoticed = mutation.judge(
        "header-leak",
        inventory,
        mutation.RunResult(
            "header-leak",
            {trail: "passed", credential: "passed"},
            leaked_reads=frozenset({trail, credential}),
        ),
    )
    assert not unnoticed.ok
    [problem] = unnoticed.problems
    assert problem.startswith("every interaction case still passes with header-leak")

    errored = mutation.judge(
        "header-leak",
        inventory,
        mutation.RunResult(
            "header-leak",
            {trail: "error", credential: "failed"},
            leaked_reads=frozenset({credential}),
        ),
    )
    assert not errored.ok
    assert any("errored" in problem for problem in errored.problems)


def test_a_failure_without_a_leaked_summary_read_is_not_credited() -> None:
    """A case that failed under header-leak, but whose read left no leaked read, proves nothing.

    The harness records, after each response, whether the exception's summary reads hold
    the bearer token the request sent; a failing case whose read did not is a failure
    about something else (or no read at all), not evidence of the leak.
    """
    inventory = _audit_inventory()
    trail, credential = f"{AUDIT.as_posix()}::test_trail", f"{AUDIT.as_posix()}::test_credential"

    unproven = mutation.judge(
        "header-leak",
        inventory,
        mutation.RunResult("header-leak", {trail: "passed", credential: "failed"}),
    )
    assert not unproven.ok
    [problem] = unproven.problems
    assert problem.startswith(f"{credential} failed under header-leak, but the mutated route")
    assert "not evidence of the leak" in problem

    # One credited failure is enough; a second, unproven one is not a problem.
    mixed = mutation.judge(
        "header-leak",
        inventory,
        mutation.RunResult(
            "header-leak",
            {trail: "failed", credential: "failed"},
            leaked_reads=frozenset({credential}),
        ),
    )
    assert mixed.ok, mixed.problems


def test_cases_with_leaked_read_come_from_the_harness_audit_lines() -> None:
    """Only `kind: audit` lines with `bearer_in_summary_read: true` name a case."""
    events: list[dict[str, object]] = [
        {"case": "a", "kind": "audit", "bearer_in_summary_read": True},
        {"case": "b", "kind": "audit", "bearer_in_summary_read": False},
        {"case": "c", "kind": "read", "bearer_in_summary_read": True},
        {"case": "", "kind": "audit", "bearer_in_summary_read": True},
        {"kind": "audit", "bearer_in_summary_read": True},
    ]
    assert mutation.cases_with_leaked_read(events) == frozenset({"a", ""})
    assert mutation.cases_with_leaked_read([]) == frozenset()


def test_a_non_assertion_failure_is_an_invalid_run_not_a_detection() -> None:
    """A FileNotFoundError or AttributeError failure under header-leak invalidates the run."""
    inventory = _audit_inventory()
    trail, credential = f"{AUDIT.as_posix()}::test_trail", f"{AUDIT.as_posix()}::test_credential"

    broken = mutation.judge(
        "header-leak",
        inventory,
        mutation.RunResult(
            "header-leak", {trail: "error:FileNotFoundError", credential: "error:FileNotFoundError"}
        ),
    )
    assert not broken.ok
    [problem] = [item for item in broken.problems if item.startswith("the run under header-leak")]
    assert f"{credential} (FileNotFoundError)" in problem
    assert f"{trail} (FileNotFoundError)" in problem
    assert "exception other than AssertionError" in problem

    # The review's case: `dict(request.headers)` over a local string raises AttributeError
    # in both no-op tests; neither is credited, and the run is invalid.
    raised = mutation.judge(
        "header-leak",
        inventory,
        mutation.RunResult(
            "header-leak",
            {trail: "error:AttributeError", credential: "error:AttributeError"},
            leaked_reads=frozenset(),
        ),
    )
    assert not raised.ok
    assert any(f"{credential} (AttributeError)" in item for item in raised.problems)
    assert any("every interaction case still passes" in item for item in raised.problems)


def test_check_reports_an_empty_student_file_without_mutating_anything(tmp_path: Path) -> None:
    """On a file with no tests the inventory is the whole verdict: no mutated run is made."""
    root = tmp_path
    (root / "tests/student").mkdir(parents=True)
    (root / GUARDRAIL).write_text("", encoding="utf-8")
    (root / AUDIT).write_text("", encoding="utf-8")

    bypass = mutation.check("validation-bypass", root=root)
    leak = mutation.check("header-leak", root=root)

    assert not bypass.ok and not leak.ok
    assert bypass.problems == [
        "tests/student/test_output_guardrail.py ran no test; write the tests the template marks"
    ]
    assert leak.problems == [
        "tests/student/test_audit.py ran no test; write the tests the template marks"
    ]
    assert not (root / "src").exists()


def test_collect_inventory_refuses_a_missing_or_invalid_student_file(tmp_path: Path) -> None:
    """A missing file and a syntax error are tooling errors with the file named."""
    with pytest.raises(mutation.MutationError, match="does not exist"):
        mutation.collect_inventory(GUARDRAIL, tmp_path)
    (tmp_path / "tests/student").mkdir(parents=True)
    (tmp_path / AUDIT).write_text("def (:\n", encoding="utf-8")
    with pytest.raises(mutation.MutationError, match="not valid Python"):
        mutation.collect_inventory(AUDIT, tmp_path)


def test_a_student_file_the_guard_rejects_is_never_executed(tmp_path: Path) -> None:
    """The counterexample is refused by the inventory and by its mutation: nothing runs."""
    root = tmp_path
    (root / "tests/student").mkdir(parents=True)
    tests = ["import pytest\nimport worker.use_cases\n\nORIGINAL = worker.use_cases.__file__\n"]
    for response in mutation.RESPONSES:
        tests.append(
            f"\n\nasync def test_{response}(harness):\n"
            f'    await harness.run_worker("{response}")\n'
            "    assert worker.use_cases.__file__ == ORIGINAL\n"
        )
    (root / GUARDRAIL).write_text("".join(tests), encoding="utf-8")

    with pytest.raises(mutation.MutationError, match="was not run") as refused:
        mutation.collect_inventory(GUARDRAIL, root)
    message = str(refused.value)
    assert "`import worker.use_cases` is not permitted" in message
    assert "`__file__` is not permitted" in message
    assert "`test_malformed` has no `assert` comparing the `.state`" in message
    with pytest.raises(mutation.MutationError, match="was not run"):
        mutation.check("validation-bypass", root=root)
    assert not (root / "src").exists()
    assert not list(root.glob("**/report.xml"))


# --- Case identities and junit outcomes ------------------------------------------------------


def test_trace_names_the_current_case_by_its_full_node_id_for_either_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The recorded case is the full node id: the student file, the class chain, the name."""
    monkeypatch.setenv(
        trace.CURRENT_TEST_VARIABLE, f"{AUDIT.as_posix()}::TestA::test_y[a-b] (call)"
    )
    assert trace.current_case() == f"{AUDIT.as_posix()}::TestA::test_y[a-b]"
    monkeypatch.setenv(trace.CURRENT_TEST_VARIABLE, f"{GUARDRAIL.as_posix()}::test_z (setup)")
    assert trace.current_case() == f"{GUARDRAIL.as_posix()}::test_z"
    monkeypatch.setenv(trace.CURRENT_TEST_VARIABLE, "test_audit.py::Outer::t (call)")
    assert trace.current_case() == f"{AUDIT.as_posix()}::Outer::t"
    monkeypatch.delenv(trace.CURRENT_TEST_VARIABLE)
    assert trace.current_case() == ""

    recorded = tmp_path / "trace.jsonl"
    trace.record(None, {"kind": "worker"})
    trace.record(recorded, {"kind": "worker", "response": "valid"})
    [event] = trace.read_events(recorded)
    assert event == {"case": "", "kind": "worker", "response": "valid"}


def test_junit_identity_matches_the_trace_identity_for_either_file() -> None:
    """`classname` plus `name` from the report rebuilds exactly the node id the trace wrote."""
    assert (
        trace.junit_case_id("tests.student.test_audit", "test_z") == f"{AUDIT.as_posix()}::test_z"
    )
    assert trace.junit_case_id("tests.student.test_output_guardrail.TestA", "test_y[p]") == (
        f"{GUARDRAIL.as_posix()}::TestA::test_y[p]"
    )
    assert (
        trace.junit_case_id("test_audit.Outer.Inner", "t") == f"{AUDIT.as_posix()}::Outer::Inner::t"
    )
    assert trace.junit_case_id("tests.other.other", "test_y") == "tests.other.other::test_y"
    assert trace.junit_case_id("", "test_y") == "test_y"
    for node in (f"{AUDIT.as_posix()}::TestA::test_y", f"{GUARDRAIL.as_posix()}::test_z[p]"):
        path, _, params = node.partition("[")
        names = path.split("::")
        names[0] = names[0].replace("/", ".").removesuffix(".py")
        names[-1] += ("[" + params) if params else ""
        assert trace.junit_case_id(".".join(names[:-1]), names[-1]) == trace.case_id(node)


def _report(path: Path, rows: list[tuple[str, str, str, str]]) -> Path:
    """Write a junit report: (classname, name, outcome element or "", message)."""
    cases = "".join(
        f"<testcase classname='{classname}' name='{name}' time='0.1'>"
        + (
            f"<{outcome} message={quoteattr(message)}>{escape(message)}</{outcome}>"
            if outcome
            else ""
        )
        + "</testcase>"
        for classname, name, outcome, message in rows
    )
    path.write_text(
        "<?xml version='1.0'?><testsuites><testsuite name='pytest'>"
        + cases
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def test_parse_junit_keeps_same_named_methods_apart_and_rejects_duplicates(tmp_path: Path) -> None:
    """Two classes' `test_x` are two outcomes; one identity twice is a tooling error."""
    module = "tests.student.test_audit"
    report = tmp_path / "report.xml"

    outcomes = mutation._parse_junit(
        _report(
            report,
            [
                (f"{module}.TestWeak", "test_x", "", ""),
                (f"{module}.TestStrong", "test_x", "failure", "assert 1 == 2"),
                (module, "test_y", "error", "fixture 'x' not found"),
                (module, "test_z", "skipped", "skipped"),
            ],
        )
    )
    assert outcomes == {
        f"{AUDIT.as_posix()}::TestWeak::test_x": "passed",
        f"{AUDIT.as_posix()}::TestStrong::test_x": "failed",
        f"{AUDIT.as_posix()}::test_y": "error",
        f"{AUDIT.as_posix()}::test_z": "skipped",
    }
    with pytest.raises(mutation.MutationError, match="twice"):
        mutation._parse_junit(
            _report(report, [(module, "test_x", "", ""), (module, "test_x", "failure", "x")])
        )
    assert mutation._parse_junit(tmp_path / "absent.xml") == {}


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "FileNotFoundError: [Errno 2] No such file or directory: '/tmp/x/schemas/s.json'",
            "error:FileNotFoundError",
        ),
        ("ModuleNotFoundError: No module named 'worker.guardrail'", "error:ModuleNotFoundError"),
        (
            "ImportError: cannot import name 'validate_summary' from 'worker.guardrail'",
            "error:ImportError",
        ),
        ("AttributeError: 'str' object has no attribute 'headers'", "error:AttributeError"),
        ("TypeError: 'NoneType' object is not subscriptable", "error:TypeError"),
        ("RuntimeError: no sink was composed", "error:RuntimeError"),
        ("Failed: DID NOT RAISE <class 'KeyError'>", "error:Failed"),
        ("KeyError: 'summary_read'", "error:KeyError"),
        ("AssertionError: the token is in the trail\nassert 'Bearer' not in '...'", "failed"),
        ("AssertionError", "failed"),
        ("assert 'authorization' not in 'authorization bearer'", "failed"),
        ("assert not True", "failed"),
        ("assertion_helper.Error: x", "error:Error"),
    ],
    ids=[
        "file",
        "module",
        "import",
        "attribute",
        "type",
        "runtime",
        "did-not-raise",
        "key",
        "assertion-message",
        "bare-assertion",
        "rewritten-assert",
        "rewritten-not",
        "dotted-lookalike",
    ],
)
def test_only_an_assertion_failure_is_a_failed_outcome(
    tmp_path: Path, message: str, expected: str
) -> None:
    """A junit failure is `failed` only for `AssertionError`; any other is an error by name."""
    report = _report(
        tmp_path / "report.xml",
        [("tests.student.test_audit", "test_credential", "failure", message)],
    )

    assert mutation._parse_junit(report) == {f"{AUDIT.as_posix()}::test_credential": expected}


def test_the_failure_exception_is_read_from_the_type_attribute_or_the_texts_last_line(
    tmp_path: Path,
) -> None:
    """A `type` attribute wins; with no usable message, the traceback's `path:line: Name`."""
    report = tmp_path / "report.xml"
    report.write_text(
        "<?xml version='1.0'?><testsuites><testsuite name='pytest'>"
        "<testcase classname='tests.student.test_audit' name='test_typed'>"
        "<failure type='builtins.AttributeError' message='assert 1 == 1'>x</failure></testcase>"
        "<testcase classname='tests.student.test_audit' name='test_located'>"
        "<failure message=''>def test_located():\n&gt;       assert token not in text\n"
        "E       assert 'x' not in 'x'\n\ntests/student/test_audit.py:40: AssertionError"
        "</failure></testcase>"
        "<testcase classname='tests.student.test_audit' name='test_unknown'>"
        "<failure message=''></failure></testcase>"
        "</testsuite></testsuites>",
        encoding="utf-8",
    )

    assert mutation._parse_junit(report) == {
        f"{AUDIT.as_posix()}::test_typed": "error:AttributeError",
        f"{AUDIT.as_posix()}::test_located": "failed",
        f"{AUDIT.as_posix()}::test_unknown": "error:unknown",
    }


# --- The whole path, against probe modules ----------------------------------------------------

PROBE_WORKER_MODULE = '''"""Probe worker: one guardrail call, the raw text stored, no policy."""

from enum import StrEnum

from domain.contracts import ExceptionState, ModelRequest
from worker.guardrail import validate_summary


class ProcessingDisposition(StrEnum):
    """One acknowledgement."""

    ACK = "ACK"


class WorkerApplication:
    """The smallest worker the harness can run; it implements no output policy."""

    def __init__(self, repository, provider, procedures, *, audit, clock, maximum_attempts=3):
        """Keep the collaborators the harness hands over."""
        self._repository = repository
        self._provider = provider
        self._procedures = procedures

    async def process(self, job, *, delivery_count):
        """Call the provider, hand the text to the guardrail once, store the text."""
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
        validate_summary(answer.text)
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=answer.text,
        )
        return ProcessingDisposition.ACK
'''

PROBE_ROUTE_MODULE = '''"""Probe route: one read event with a placeholder field, no access rule."""

from fastapi import FastAPI


def create_app(
    application,
    repository,
    retrieval,
    objects,
    documents,
    *,
    experiment=None,
    version_two=None,
    readiness=None,
    build_version="dev",
    lifespan=None,
    token_verifier=None,
    audit=None,
):
    """Compose the smallest application the harness can read through; no access rule."""
    app = FastAPI()

    @app.get("/api/v1/exceptions/{exception_id}")
    async def get_exception(exception_id: str) -> dict:
        await audit.record("summary_read", exception_id=exception_id, details={"subject": "probe"})
        return {"exception_id": exception_id}

    return app
'''

PROBE_HEADER = '''"""Probe audit tests."""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API."""
    return InteractionHarness()
'''

NOOP_AUDIT_TESTS = (
    PROBE_HEADER
    + '''

async def test_first(harness: InteractionHarness) -> None:
    """Runs and reads; asserts nothing about the trail's content."""
    record = await harness.run_worker("valid")
    async with harness.bearer_client("dispatcher-valid") as client:
        await client.get(f"/api/v1/exceptions/{record.exception_id}")
    assert harness.audit_trail(record.exception_id) is not None


async def test_second(harness: InteractionHarness) -> None:
    """Runs and reads; asserts nothing about the trail's content."""
    record = await harness.run_worker("manipulated")
    async with harness.bearer_client("dispatcher-valid") as client:
        await client.get(f"/api/v1/exceptions/{record.exception_id}")
    assert harness.audit_trail(record.exception_id) is not None
'''
)

CREDENTIAL_AUDIT_TESTS = NOOP_AUDIT_TESTS.replace(
    '    record = await harness.run_worker("manipulated")\n'
    '    async with harness.bearer_client("dispatcher-valid") as client:\n'
    '        await client.get(f"/api/v1/exceptions/{record.exception_id}")\n'
    "    assert harness.audit_trail(record.exception_id) is not None\n",
    '    record = await harness.run_worker("manipulated")\n'
    '    async with harness.bearer_client("dispatcher-valid") as client:\n'
    '        await client.get(f"/api/v1/exceptions/{record.exception_id}")\n'
    "    text = harness.audit_text(record.exception_id)\n"
    '    assert harness.token("dispatcher-valid") not in text\n',
)
PROBE_DIRECTORIES = (
    "src",
    "schemas",
    "config",
    "tests/security",
    "tests/doubles",
    "tests/fixtures",
    "infra/corpus",
)
PROBE_FILES = ("tests/__init__.py", "tests/e2e/baseline-exception.json")


def _probe_root(tmp_path: Path) -> Path:
    """Build a scratch Task tree: the shipped tooling and shared code, probe student modules.

    The real ``src/`` is copied, then the two student-editable modules are replaced by the
    probes, so no shipped student file is read or run by this test.
    """
    root = tmp_path / "root"
    for relative in PROBE_DIRECTORIES:
        shutil.copytree(
            TASK_ROOT / relative,
            root / relative,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for relative in PROBE_FILES:
        if (TASK_ROOT / relative).is_file():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(TASK_ROOT / relative, root / relative)
    options = tomllib.loads((TASK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "pytest"
    ]["ini_options"]
    (root / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        + "".join(f"{key} = {json.dumps(value)}\n" for key, value in options.items()),
        encoding="utf-8",
    )
    (root / "src/worker/use_cases.py").write_text(PROBE_WORKER_MODULE, encoding="utf-8")
    (root / "src/api/routes.py").write_text(PROBE_ROUTE_MODULE, encoding="utf-8")
    (root / "tests/student").mkdir(parents=True, exist_ok=True)
    (root / GUARDRAIL).write_text(PROBE_HEADER, encoding="utf-8")
    return root


def test_header_leak_is_judged_by_the_tests_assertions_in_a_complete_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Against a complete copy, a no-op audit test survives the leak; a credential test fails it.

    Both runs go through the real `check`: the inventory run as written, then the mutated
    run against a workspace that holds `schemas/` beside the mutated `src/`. The worker
    probe calls the guardrail, so a workspace without the schema would make every case
    fail with `FileNotFoundError` and a no-op test would look like a detection; here the
    no-op tests pass under the leak and the verdict names them, and only the test that
    asserts the token's absence fails and proves the mutation, credited because the
    harness recorded its read leaving a summary read that holds the bearer token.
    """
    root = _probe_root(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(root / "src"))
    monkeypatch.delenv(trace.TRACE_VARIABLE, raising=False)
    first, second = f"{AUDIT.as_posix()}::test_first", f"{AUDIT.as_posix()}::test_second"

    (root / AUDIT).write_text(NOOP_AUDIT_TESTS, encoding="utf-8")
    insufficient = mutation.check("header-leak", root=root)

    assert insufficient.required == {first, second}
    assert not insufficient.ok
    assert insufficient.problems == [
        f"every interaction case still passes with header-leak: none of {first}, {second} "
        "noticed the leaked headers"
    ]

    (root / AUDIT).write_text(CREDENTIAL_AUDIT_TESTS, encoding="utf-8")
    proven = mutation.check("header-leak", root=root)

    assert proven.required == {first, second}
    assert proven.ok, proven.problems
