"""Coldline.

===================

File:              tests/unit/security/test_guardrail_binding.py
Component:         Unit tests — Static guardrail-binding and reach check
Purpose:           Prove the check accepts a worker that imports and calls the supplied guardrail
                    and a route that stays application code, and rejects every way the name or
                    the module could be rebound and every spelled path to the test runner.
Interacts With:    tests/security/guardrail_binding.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Trusted static analysis, verified bindings, a closed reach for application code
Tools:             Python 3.12, pytest

Every test feeds a synthetic fragment to the check; none reads the shipped
`src/worker/use_cases.py` or `src/api/routes.py`, whose state is the student's (the
assessed row reads them). The fragments are probes, one import and one call, or one route
with one record call, not the Task's worker or route. The snippets that spell `exec`,
`_pytest.reports` or `__globals__` are source text handed to the parser; nothing here
executes them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.security import guardrail_binding as binding

ACCEPTED = '''"""Worker probe."""

from worker.guardrail import REVIEW_MESSAGE, RejectedSummary, validate_summary


async def process(answer_text):
    verdict = validate_summary(answer_text)
    return isinstance(verdict, RejectedSummary), REVIEW_MESSAGE
'''

ROUTE = '''"""Route probe."""

from fastapi import FastAPI
from starlette.types import Lifespan


def create_app(audit, lifespan: Lifespan[FastAPI] | None = None):
    app = FastAPI(lifespan=lifespan)

    @app.get("/api/v1/exceptions/{exception_id}")
    async def get_exception(exception_id: str) -> dict:
        await audit.record("summary_read", exception_id=exception_id, details={"subject": "probe"})
        return {"exception_id": exception_id}

    return app
'''

DOCSTRING = '"""Worker probe."""\n\n'
ROUTE_DOCSTRING = '"""Route probe."""\n\n'


def _findings(source: str) -> list[str]:
    return binding.findings_for_source(source)


def _route_findings(source: str) -> list[str]:
    return binding.findings_for_source(source, binding.ROUTES_PATH)


def test_the_permitted_import_and_a_direct_call_pass() -> None:
    """One module-level import of the name, used only as a callee: nothing to report."""
    assert _findings(ACCEPTED) == []
    two_calls = ACCEPTED + "\n\ndef again(text):\n    return validate_summary(text)\n"
    assert _findings(two_calls) == []


def test_a_route_that_is_application_code_passes() -> None:
    """A route module with ordinary imports (`starlette.types` included) has nothing to report."""
    assert _route_findings(ROUTE) == []


def test_a_worker_without_the_import_is_named() -> None:
    """The starter's shape (no guardrail import) is the one finding the import rule makes."""
    found = _findings('"""Worker."""\n\n\ndef process(answer):\n    return parse(answer)\n')
    assert found == [
        "the worker does not import `validate_summary` from `worker.guardrail`; "
        f"{binding.IMPORT_HINT}"
    ]


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("import worker.guardrail\n", "`import worker.guardrail` is not permitted"),
        ("import worker\n", "`import worker` is not permitted"),
        ("import worker.guardrail as g\n", "`import worker.guardrail` is not permitted"),
        ("from worker import guardrail\n", "`from worker import guardrail` is not permitted"),
        ("from .guardrail import validate_summary\n", "a relative import of the guardrail"),
        ("from . import guardrail\n", "a relative import of the guardrail"),
        ("from worker.guardrail import *\n", "`from worker.guardrail import *` is not permitted"),
        (
            "from worker.guardrail import validate_summary as check\n",
            "`validate_summary as check` rebinds the guardrail",
        ),
        (
            "from worker.guardrail import load_schema as validate_summary\n",
            "`load_schema as validate_summary` rebinds the guardrail",
        ),
        (
            "from mine.parser import validate_summary\n",
            "`validate_summary` imported from `mine.parser` is not the supplied guardrail",
        ),
    ],
    ids=[
        "import-module",
        "import-package",
        "import-as",
        "from-package",
        "relative",
        "relative-package",
        "star",
        "alias-out",
        "alias-in",
        "other-module",
    ],
)
def test_every_other_way_to_reach_the_guardrail_is_a_finding(statement: str, expected: str) -> None:
    """Only `from worker.guardrail import validate_summary` reaches the supplied guardrail."""
    found = _findings(ACCEPTED.replace(DOCSTRING, DOCSTRING + statement))
    assert any(expected in finding for finding in found), (statement, found)


def test_a_second_import_or_one_inside_a_function_is_a_finding() -> None:
    """The import is one statement, at module level."""
    twice = ACCEPTED + "\nfrom worker.guardrail import validate_summary\n"
    assert any("imported 2 times" in finding for finding in _findings(twice))

    nested = ACCEPTED.replace(
        "    verdict = validate_summary(answer_text)\n",
        "    from worker.guardrail import validate_summary\n\n"
        "    verdict = validate_summary(answer_text)\n",
    )
    found = _findings(nested)
    assert any("imported 2 times" in finding for finding in found)
    assert any("must be at module level" in finding for finding in found)


@pytest.mark.parametrize(
    ("snippet", "how"),
    [
        ("def validate_summary(raw):\n    return raw\n", "a function definition"),
        ("async def validate_summary(raw):\n    return raw\n", "a function definition"),
        ("class validate_summary:\n    pass\n", "a class definition"),
        ("validate_summary = lambda raw: raw\n", "an assignment to the name"),
        ("validate_summary: object = None\n", "an assignment to the name"),
        ("(validate_summary := None)\n", "an assignment to the name"),
        ("for validate_summary in ():\n    pass\n", "an assignment to the name"),
        ("del validate_summary\n", "an assignment to the name"),
        ("def helper(validate_summary):\n    return validate_summary\n", "a parameter"),
        ("helper = lambda validate_summary: validate_summary\n", "a parameter"),
        (
            "try:\n    pass\nexcept Exception as validate_summary:\n    pass\n",
            "an exception handler",
        ),
        ("def helper():\n    global validate_summary\n", "a global or nonlocal statement"),
        ("match 1:\n    case validate_summary:\n        pass\n", "a match capture"),
        ("guardrail.validate_summary = None\n", "an attribute assignment"),
    ],
    ids=[
        "def",
        "async-def",
        "class",
        "assign",
        "annotated",
        "walrus",
        "for",
        "del",
        "parameter",
        "lambda",
        "handler",
        "global",
        "match",
        "attribute",
    ],
)
def test_every_rebinding_of_the_name_is_named_by_how(snippet: str, how: str) -> None:
    """A definition, an assignment target, a parameter, a handler, a capture: each is a finding."""
    found = _findings(ACCEPTED + "\n" + snippet)
    assert any(f"{how} rebinds `validate_summary`" in finding for finding in found), (
        snippet,
        found,
    )


def test_handing_the_function_to_another_name_is_a_finding() -> None:
    """`check = validate_summary` lets a call through `check` escape the mutation."""
    aliased = ACCEPTED + "\ncheck = validate_summary\n"
    found = _findings(aliased)
    assert any("used other than as the callee of a call" in finding for finding in found), found
    passed = ACCEPTED + "\nresult = list(map(validate_summary, ['{}']))\n"
    assert any("used other than as the callee" in finding for finding in _findings(passed))


@pytest.mark.parametrize(
    "snippet",
    [
        "import sys\nsys.modules['worker.guardrail'] = None\n",
        "import importlib\nimportlib.reload(validate_summary)\n",
        "setattr(validate_summary, 'x', 1)\n",
        "globals()['validate_summary'] = None\n",
        "exec('validate_summary = None')\n",
        "__import__('worker.guardrail')\n",
    ],
    ids=["sys-modules", "importlib", "setattr", "globals", "exec", "dunder-import"],
)
def test_runtime_rebinding_doors_are_findings(snippet: str) -> None:
    """The names that rebind a module or a global at runtime have no place in the worker."""
    found = _findings(ACCEPTED + "\n" + snippet)
    assert any("can rebind a module or a global at runtime" in finding for finding in found), (
        snippet,
        found,
    )


# --- The reach rules, over both files -------------------------------------------------------

RUNNER_IMPORTS = [
    "import pytest\n",
    "import _pytest\n",
    "import _pytest.reports\n",
    "from _pytest.reports import TestReport\n",
    "import sys\n",
    "from sys import modules\n",
    "import importlib\n",
    "import importlib.util\n",
    "from importlib import import_module\n",
    "import builtins\n",
    "import gc\n",
    "import inspect\n",
    "import ctypes\n",
    "import ctypes.util as cu\n",
    "import types\n",
    "from types import ModuleType\n",
    "import runpy\n",
]


@pytest.mark.parametrize("statement", RUNNER_IMPORTS, ids=[s.strip() for s in RUNNER_IMPORTS])
def test_an_import_of_a_runner_module_is_a_finding_in_both_files(statement: str) -> None:
    """`pytest`, `_pytest`, `sys`, `importlib`, ... and their submodules are refused as imports."""
    worker = _findings(ACCEPTED.replace(DOCSTRING, DOCSTRING + statement))
    route = _route_findings(ROUTE.replace(ROUTE_DOCSTRING, ROUTE_DOCSTRING + statement))
    for found in (worker, route):
        assert any(
            "is not permitted in application code" in item and "test runner" in item
            for item in found
        ), (statement, found)


def test_a_module_whose_name_merely_ends_like_a_runner_module_is_not_a_finding() -> None:
    """`starlette.types` is not `types`; `api.security.tokens` is not `sys`."""
    assert _route_findings(ROUTE) == []
    worker = ACCEPTED.replace(DOCSTRING, DOCSTRING + "from starlette.types import Lifespan\n")
    assert _findings(worker) == []
    worker = ACCEPTED.replace(DOCSTRING, DOCSTRING + "from api.security.tokens import Principal\n")
    assert _findings(worker) == []


@pytest.mark.parametrize(
    ("snippet", "name"),
    [
        ("exec('x = 1')\n", "exec"),
        ("eval('1')\n", "eval"),
        ("code = compile('x = 1', '<s>', 'exec')\n", "compile"),
        ("__import__('_pytest')\n", "__import__"),
        ("globals()['x'] = 1\n", "globals"),
        ("setattr(FastAPI, 'x', 1)\n", "setattr"),
        ("delattr(FastAPI, 'title')\n", "delattr"),
        ("run = exec\n", "exec"),
        ("table = __builtins__\n", "__builtins__"),
    ],
    ids=["exec", "eval", "compile", "import", "globals", "setattr", "delattr", "alias", "builtins"],
)
def test_a_dynamic_name_is_a_finding_in_both_files_called_or_handed_on(
    snippet: str, name: str
) -> None:
    """`exec`, `eval`, `compile`, `__import__`, `globals`, `setattr`, `delattr`, `__builtins__`."""
    worker = _findings(ACCEPTED + "\n" + snippet)
    route = _route_findings(ROUTE + "\n" + snippet)
    for found in (worker, route):
        assert any(f"`{name}` is not permitted in application code" in item for item in found), (
            snippet,
            found,
        )


@pytest.mark.parametrize(
    "snippet",
    [
        "TABLE = FastAPI.__dict__\n",
        "SCOPE = create_app.__globals__\n",
        "CODE = create_app.__code__\n",
        "BUILTINS = create_app.__builtins__\n",
        "KIND = FastAPI().__class__\n",
        "MODULE = FastAPI.__module__\n",
        "create_app.__wrapped__ = None\n",
    ],
    ids=["dict", "globals", "code", "builtins", "class", "module", "wrapped"],
)
def test_a_dunder_attribute_is_a_finding_in_both_files(snippet: str) -> None:
    """The five named doors, and every other dunder attribute, are refused."""
    worker = _findings(ACCEPTED + "\n" + snippet)
    route = _route_findings(ROUTE + "\n" + snippet)
    for found in (worker, route):
        assert any("a dunder attribute reaches" in item for item in found), (snippet, found)


@pytest.mark.parametrize(
    "snippet",
    [
        "from logging import sys as runtime\n",
        "import logging\nTABLE = logging.sys.modules\n",
        "from os import sys\n",
        "import logging\nKIND = logging.types\n",
    ],
    ids=["from-alias", "attribute-chain", "from-os", "attribute-types"],
)
def test_a_runner_module_reached_through_another_module_is_a_finding(snippet: str) -> None:
    """Round 3: `logging.sys` is the same door as `import sys`, by import or by attribute."""
    worker = _findings(ACCEPTED + "\n" + snippet)
    route = _route_findings(ROUTE + "\n" + snippet)
    for found in (worker, route):
        assert any("the same door" in item for item in found), (snippet, found)


def test_a_report_patch_through_the_runner_is_named_before_it_could_run() -> None:
    """The review's attack: rewrite `TestReport.from_item_and_call` so failures report as passed.

    Spelled through `_pytest.reports`, through `sys.modules`, or through a function's
    `__globals__`, each form is at least one finding in the route module, which the
    harness imports first.
    """
    direct = ROUTE + (
        "\nfrom _pytest.reports import TestReport\n\n"
        "def _passed(item, call):\n    report = _original(item, call)\n"
        "    report.outcome = 'passed'\n    return report\n\n"
        "_original = TestReport.from_item_and_call\n"
        "TestReport.from_item_and_call = staticmethod(_passed)\n"
    )
    found = _route_findings(direct)
    assert any("`from _pytest.reports import TestReport`" in item for item in found), found

    through_modules = ROUTE + (
        "\nimport sys\n\nreports = sys.modules['_pytest.reports']\n"
        "reports.TestReport.from_item_and_call = lambda item, call: None\n"
    )
    found = _route_findings(through_modules)
    assert any("`import sys`" in item for item in found), found

    through_globals = ROUTE + "\nreports = create_app.__globals__['_pytest']\n"
    found = _route_findings(through_globals)
    assert any("`create_app.__globals__`" in item for item in found), found


def test_rules_are_chosen_by_file_name_and_other_files_are_refused() -> None:
    """`use_cases.py` gets binding and reach rules, `routes.py` reach rules, others an error."""
    assert binding.rules_for(Path("src/worker/use_cases.py")) == "worker"
    assert binding.rules_for(Path("elsewhere/use_cases.py")) == "worker"
    assert binding.rules_for(Path("src/api/routes.py")) == "route"
    with pytest.raises(binding.GuardrailBindingError, match="not an application file"):
        binding.rules_for(Path("src/api/security/tokens.py"))
    # The route module owes no guardrail import; the worker does.
    assert _route_findings(ROUTE) == []
    assert any("does not import `validate_summary`" in item for item in _findings(ROUTE))


def test_findings_are_deduplicated_and_a_syntax_error_is_a_finding() -> None:
    """One finding per distinct problem; an unparsable file is reported as such."""
    found = _findings(ACCEPTED + "\ncheck = validate_summary\ncheck = validate_summary\n")
    assert len(found) == len(set(found))
    [finding] = _findings("def (:\n")
    assert finding.startswith("src/worker/use_cases.py is not valid Python: ")
    [finding] = _route_findings("def (:\n")
    assert finding.startswith("src/api/routes.py is not valid Python: ")


def test_application_findings_cover_both_files_under_a_root(tmp_path: Path) -> None:
    """Both files are read from the root and each finding carries its file's path."""
    (tmp_path / "src/worker").mkdir(parents=True)
    (tmp_path / "src/api").mkdir()
    (tmp_path / "src/worker/use_cases.py").write_text(ACCEPTED, encoding="utf-8")
    (tmp_path / "src/api/routes.py").write_text(ROUTE, encoding="utf-8")
    assert binding.application_findings(tmp_path) == []

    (tmp_path / "src/api/routes.py").write_text(ROUTE + "\nimport gc\n", encoding="utf-8")
    (tmp_path / "src/worker/use_cases.py").write_text(
        ACCEPTED + "\ncheck = validate_summary\n", encoding="utf-8"
    )
    found = binding.application_findings(tmp_path)
    assert len(found) == 2
    assert found[0].startswith("src/worker/use_cases.py: ")
    assert found[1].startswith("src/api/routes.py: ") and "`import gc`" in found[1]

    (tmp_path / "src/api/routes.py").unlink()
    with pytest.raises(binding.GuardrailBindingError, match="could not be read"):
        binding.application_findings(tmp_path)


def test_findings_read_the_file_and_main_reports_the_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`findings(path)` reads bytes; `main` exits 0 clean, 1 with findings, 2 unreadable."""
    worker = tmp_path / "use_cases.py"
    route = tmp_path / "routes.py"
    worker.write_text(ACCEPTED, encoding="utf-8")
    route.write_text(ROUTE, encoding="utf-8")
    assert binding.findings(worker) == []
    assert binding.findings(route) == []
    assert binding.main([str(worker), str(route)]) == 0
    out = capsys.readouterr().out
    assert "src/worker/use_cases.py imports `validate_summary` from `worker.guardrail`" in out
    assert "src/api/routes.py reaches nothing beyond application code" in out

    worker.write_text(ACCEPTED + "\ncheck = validate_summary\n", encoding="utf-8")
    route.write_text(ROUTE + "\nimport inspect\n", encoding="utf-8")
    assert binding.main([str(worker), str(route)]) == 1
    captured = capsys.readouterr()
    assert "does not call the supplied guardrail by its imported name" in captured.err
    assert "used other than as the callee of a call" in captured.err
    assert "src/api/routes.py reaches beyond application code" in captured.err
    assert "`import inspect`" in captured.err

    with pytest.raises(binding.GuardrailBindingError, match="could not be read"):
        binding.findings(tmp_path / "absent" / "use_cases.py")
    assert binding.main([str(tmp_path / "absent" / "use_cases.py")]) == 2
    assert binding.main([str(tmp_path / "tokens.py")]) == 2
