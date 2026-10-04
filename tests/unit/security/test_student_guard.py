"""Coldline.

===================

File:              tests/unit/security/test_student_guard.py
Component:         Unit tests — Static student-test guard
Purpose:           Prove the guard accepts tests that describe outcomes and rejects every way a
                    test could inspect its environment instead, before any execution, for both
                    of this Task's student files.
Interacts With:    tests/security/student_guard.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Trusted static analysis, closed import set, flat name rules, assertions
                    over outcomes
Tools:             Python 3.12, pytest, tomllib

Every test here feeds a synthetic source to the guard; none reads the shipped student
files, whose state is the student's (the assessed row and `poe student-guard` read them).
The synthetic sources are probes, the smallest tests that satisfy or break one rule: a
guardrail test that asserts one state, an audit test that asserts the trail is there, a
credential test that asserts the token is not; none shows the Task's own answers. The
authoring suite checks the shipped templates and the private completions separately. One
test runs the real `poe student-tests` sequence in a scratch project, to prove a rejected
file's module-level code never executes through that command. The snippets that spell
`eval`, `__file__`, `ForwardRef` or `pytest.fixture` are source text handed to the parser;
nothing here executes them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tomllib
from pathlib import Path

import pytest

from tests.security import student_guard
from tests.security.student_guard import FileRules

TASK_ROOT = Path(__file__).resolve().parents[3]
GUARDRAIL = student_guard.STUDENT_FILES["test_output_guardrail.py"]
AUDIT = student_guard.STUDENT_FILES["test_audit.py"]

HEADER = '''"""Student tests."""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API."""
    return InteractionHarness()
'''

GUARDRAIL_TEST = '''

async def test_one_response_is_stored(harness: InteractionHarness) -> None:
    """The record the worker left has a state."""
    record = await harness.run_worker("valid")

    assert record.state == "COMPLETED"
'''

TRAIL_TEST = '''

async def test_one_read_leaves_a_trail(harness: InteractionHarness) -> None:
    """The trail holds records after one read."""
    record = await harness.run_worker("valid")
    async with harness.bearer_client("dispatcher-valid") as client:
        response = await client.get(f"/api/v1/exceptions/{record.exception_id}")

    assert response.status_code == 200
    trail = harness.audit_trail(record.exception_id)
    assert trail
'''

CREDENTIAL_TEST = '''

async def test_no_record_contains_the_token(harness: InteractionHarness) -> None:
    """The token is nowhere in the trail."""
    record = await harness.run_worker("valid")
    async with harness.bearer_client("dispatcher-valid") as client:
        await client.get(f"/api/v1/exceptions/{record.exception_id}")

    text = harness.audit_text(record.exception_id)
    assert harness.token("dispatcher-valid") not in text
'''

GUARDRAIL_ACCEPTED = HEADER + GUARDRAIL_TEST
AUDIT_ACCEPTED = HEADER + TRAIL_TEST + CREDENTIAL_TEST
STATE_ASSERT = '    assert record.state == "COMPLETED"\n'
SIGNATURE = '(harness: InteractionHarness) -> None:\n    """The record'
RENAME = "rename it, for example to `resp`"


def _guard(source: str | bytes, rules: FileRules = GUARDRAIL) -> list[str]:
    return student_guard.findings_for_source(source, rules)


def _line_of(source: str, needle: str) -> int:
    """Return the 1-based line of the first line containing ``needle``."""
    return next(number for number, line in enumerate(source.splitlines(), 1) if needle in line)


def _named(found: list[str], name: str) -> list[int]:
    """Return the lines on which ``name`` is reported as a forbidden name."""
    prefix = "line "
    return [
        int(finding[len(prefix) :].split(":", 1)[0])
        for finding in found
        if finding.startswith(prefix)
        and f"`{name}` is not permitted in the student file" in finding
    ]


def _file_counterexample() -> str:
    """Return the counterexample: three tests that assert where the worker module lives.

    Each test runs the worker with its response, as the inventory requires, and then
    asserts only that the imported worker module belongs to the original checkout. As
    written it passes; under the bypass mutation the copy lives elsewhere, so it fails;
    and it says nothing about any record.
    """
    tests = ["import worker.use_cases\n\nORIGINAL = worker.use_cases.__file__\n"]
    for response in ("valid", "malformed", "manipulated"):
        tests.append(
            f"\n\nasync def test_{response}(harness: InteractionHarness) -> None:\n"
            f'    """Run {response}, then look at the environment."""\n'
            f'    await harness.run_worker("{response}")\n'
            "    assert worker.use_cases.__file__ == ORIGINAL\n"
        )
    return HEADER + "\n" + "".join(tests)


def test_the_template_shape_with_no_tests_passes_vacuously() -> None:
    """The shipped templates' shape (imports, the fixture, no tests) has nothing to report.

    The executed-case inventory is what requires the tests; the guard only refuses files
    that must not be executed, and an empty one is harmless to run.
    """
    assert _guard(HEADER, GUARDRAIL) == []
    assert _guard(HEADER, AUDIT) == []
    assert _guard("", GUARDRAIL) == []


def test_tests_that_describe_outcomes_are_accepted_under_each_files_rules() -> None:
    """A guardrail test asserting a state, and the two audit tests, pass their files' rules."""
    assert _guard(GUARDRAIL_ACCEPTED, GUARDRAIL) == []
    assert _guard(GUARDRAIL_ACCEPTED.encode("utf-8"), GUARDRAIL) == []
    assert _guard(AUDIT_ACCEPTED, AUDIT) == []


def test_each_file_owes_its_own_assertion() -> None:
    """The audit tests have no `.state` assert; the guardrail test asserts nothing on the trail."""
    found = _guard(HEADER + TRAIL_TEST, GUARDRAIL)
    assert found == [
        "`test_one_read_leaves_a_trail` has no `assert` comparing the `.state` of a record "
        "obtained from `harness.run_worker(...)`: assert the stored state of the record the "
        "worker left"
    ]
    found = _guard(GUARDRAIL_ACCEPTED, AUDIT)
    assert found == [
        "`test_one_response_is_stored` has no `assert` over the audit trail: assert over "
        "`harness.audit_trail(...)` or `harness.audit_text(...)`, or a value bound from one"
    ]


def test_the_counterexample_is_rejected_before_any_execution() -> None:
    """Three tests asserting `worker.use_cases.__file__` are named three ways and never run."""
    found = _guard(_file_counterexample(), GUARDRAIL)

    assert any("`import worker.use_cases` is not permitted" in finding for finding in found)
    assert sum("`__file__` is not permitted" in finding for finding in found) == 4
    missing_state = [finding for finding in found if "has no `assert` comparing" in finding]
    assert len(missing_state) == 3


@pytest.mark.parametrize(
    "snippet, name",
    [
        ("    import sys\n    assert 'pytest' in sys.modules\n", "sys"),
        ("    assert getattr(record, 'state') == 'COMPLETED'\n", "getattr"),
        ("    assert open('config/auth.yaml').read()\n", "open"),
        ("    assert eval('1') == 1\n", "eval"),
        ("    assert __import__('os')\n", "__import__"),
        ("    assert record.__class__.__module__\n", "__class__"),
        ("    assert harness.root\n", "root"),
        ("    assert harness.repository\n", "repository"),
        ("    assert harness._audit\n", "_audit"),
        ("    assert harness.run_worker.__code__.co_filename\n", "__code__"),
        ("    import importlib\n    assert importlib\n", "importlib"),
        ("    from pathlib import Path\n    assert Path('x')\n", "Path"),
        ("    assert __spec__.origin\n", "__spec__"),
        ("    assert delattr(harness, 'root') is None\n", "delattr"),
        ("    assert ForwardRef('1')\n", "ForwardRef"),
        ("    assert get_type_hints(harness)\n", "get_type_hints"),
    ],
)
def test_each_forbidden_name_or_attribute_is_named_by_line(snippet: str, name: str) -> None:
    """A forbidden name as a Name, an Attribute, or an import binding is one finding by line."""
    source = GUARDRAIL_ACCEPTED.replace(STATE_ASSERT, snippet + STATE_ASSERT, 1)
    found = _guard(source)

    assert any(f"`{name}` is not permitted in the student file" in finding for finding in found), (
        found
    )
    assert all(finding.startswith("line ") for finding in found if "not permitted" in finding)


def test_forbidden_names_are_rejected_wherever_they_appear_with_no_binding_exemption() -> None:
    """A binding does not make a forbidden name ordinary: every position is a finding."""
    module_level = HEADER + "\neval = eval\nenvironment = eval('globals()')\n" + GUARDRAIL_TEST
    found = _guard(module_level)
    assert _named(found, "eval") == [
        _line_of(module_level, "eval = eval"),
        _line_of(module_level, "environment = eval"),
    ]
    assert [finding for finding in found if "not permitted" not in finding] == []

    every_position = GUARDRAIL_ACCEPTED.replace(
        HEADER,
        HEADER + "\nfrom typing import Any as os\n\n\ndef Path(sys, *subprocess, **inspect):\n"
        '    """Named after what it may not be."""\n    global vars\n    return 0\n\n\n'
        'class compile:\n    """Named after what it may not be."""\n',
    ).replace(
        STATE_ASSERT,
        "    for open in (1,):\n        pass\n"
        "    with harness.bearer_client('expired') as globals:\n        pass\n"
        "    resolve = lambda getattr: getattr\n"
        "    try:\n        pass\n    except Exception as builtins:\n        pass\n" + STATE_ASSERT,
    )
    found = _guard(every_position)
    names = {
        finding.split("`")[1]
        for finding in found
        if "is not permitted in the student file" in finding
    }
    assert names == {
        "os",
        "Path",
        "sys",
        "subprocess",
        "inspect",
        "vars",
        "compile",
        "open",
        "globals",
        "getattr",
        "builtins",
    }
    assert not _named(found, "resolve")


@pytest.mark.parametrize(
    "snippet",
    [
        # The review's traversal: the worker module's file through a format field.
        '    assert "{0.run_worker.__func__.__globals__[WorkerApplication].process.__code__'
        '.co_filename}".format(harness)\n',
        # The route module's file, through the app the harness holds.
        '    assert "{0.app.routes[4].endpoint.__code__.co_filename}".format(harness)\n',
        # The same through format_map.
        '    assert "{h.app.routes[4].endpoint.__code__.co_filename}".format_map({"h": harness})\n',
        # The bound method taken under another name, then called.
        '    render = "{0.root}".format\n    assert render(harness)\n',
        # A template built elsewhere and formatted with the record.
        '    assert str.format("{0.__class__.__module__}", record)\n',
    ],
    ids=["worker-file", "route-file", "format-map", "alias", "str-format"],
)
def test_a_format_field_traversal_is_rejected_by_its_attribute(snippet: str) -> None:
    """`.format` and `.format_map` are findings: a format field traverses attributes in a string.

    The guard cannot see inside a string constant; the attribute that applies the
    template is the one spelled thing, and it is refused. An f-string stays permitted
    because its expressions are AST the name rules inspect.
    """
    source = GUARDRAIL_ACCEPTED.replace(STATE_ASSERT, snippet + STATE_ASSERT, 1)
    found = _guard(source)

    assert any(
        "`format` is not permitted in the student file" in finding
        or "`format_map` is not permitted in the student file" in finding
        for finding in found
    ), found
    assert all(finding.startswith("line ") for finding in found if "not permitted" in finding)

    f_string = GUARDRAIL_ACCEPTED.replace(
        STATE_ASSERT, '    assert f"{record.exception_id}: {record.state}"\n' + STATE_ASSERT, 1
    )
    assert _guard(f_string) == []
    traversing_f_string = GUARDRAIL_ACCEPTED.replace(
        STATE_ASSERT, '    assert f"{harness.run_worker.__func__}"\n' + STATE_ASSERT, 1
    )
    assert _named(_guard(traversing_f_string), "__func__")
    # The builtin `format(value, spec)` traverses nothing and stays an ordinary name.
    builtin = GUARDRAIL_ACCEPTED.replace(
        STATE_ASSERT, '    assert format(9.2, ".1f") == "9.2"\n' + STATE_ASSERT, 1
    )
    assert _guard(builtin) == []


def test_a_local_named_like_a_harness_internal_is_accepted_but_the_attribute_is_not() -> None:
    """`records = harness.audit_trail(id)` is the file's own variable; `harness.records` is not."""
    local = AUDIT_ACCEPTED.replace(
        "    trail = harness.audit_trail(record.exception_id)\n",
        "    records = harness.audit_trail(record.exception_id)\n    trail = records\n",
    )
    assert _guard(local, AUDIT) == []
    attribute = AUDIT_ACCEPTED.replace(
        "    trail = harness.audit_trail(record.exception_id)\n",
        "    trail = harness.repository.records\n",
    )
    found = _guard(attribute, AUDIT)
    assert any("`repository`" in finding for finding in found)
    assert any("`records`" in finding for finding in found)


def test_every_dunder_is_rejected_as_an_attribute_or_a_name() -> None:
    """`x.__class__`, and any other dunder, is a finding wherever it is."""
    source = GUARDRAIL_ACCEPTED.replace(
        STATE_ASSERT,
        "    __file__ = 'x'\n"
        "    assert record.__class__\n"
        "    assert InteractionHarness.__module__\n"
        "    assert __name__\n" + STATE_ASSERT,
    )
    found = _guard(source)
    assert [finding.split(": ", 1)[0] for finding in found] == [
        f"line {_line_of(source, '__file__ = ')}",
        f"line {_line_of(source, 'assert record.__class__')}",
        f"line {_line_of(source, 'assert InteractionHarness.__module__')}",
        f"line {_line_of(source, 'assert __name__')}",
    ]


def test_imports_outside_the_four_permitted_forms_are_rejected_wherever_they_appear() -> None:
    """Only `import pytest`, the annotations future, permitted typing names and the harness."""
    accepted_imports = (
        "from __future__ import annotations\n"
        "from typing import Any\n"
        "from typing import cast as typing_cast\n"
        "import pytest\n"
        "from tests.security.interaction import InteractionHarness\n"
    )
    assert _guard(accepted_imports) == []

    for statement in (
        "import os\n",
        "import httpx\n",
        "import typing\n",
        "import pytest as pt\n",
        "import worker.use_cases\n",
        "from pytest import fixture\n",
        "from __future__ import division\n",
        "from typing import ForwardRef\n",
        "from typing import get_type_hints\n",
        "from typing import *\n",
        "from typing import NewType\n",
        "from tests.security import interaction\n",
        "from tests.security.harness import AccessHarness\n",
        "from tests.security.interaction import planted_excerpt\n",
        "from tests.security.interaction import InteractionHarness as Harness\n",
        "from tests.security.guardrail_mutation import check\n",
        "from worker.guardrail import REVIEW_MESSAGE\n",
        "from . import conftest\n",
    ):
        [finding] = [item for item in _guard(statement) if "the only imports are" in item]
        assert finding.startswith("line 1: ") and statement.strip() in finding, statement


def test_typing_imports_are_limited_to_the_annotation_allowlist() -> None:
    """Every name on the allowlist passes; every other `typing` name is refused by the import rule.

    `from typing import Any, ForwardRef` is refused for `ForwardRef` alone: the permitted
    name on the same line stays permitted, and the finding spells the refused one.
    """
    for name in sorted(student_guard.TYPING_NAMES):
        assert _guard(f"from typing import {name}\n") == [], name
        assert _guard(f"from typing import {name} as permitted_{name}\n") == [], name
    assert student_guard.TYPING_NAMES == {
        "Any",
        "Annotated",
        "Literal",
        "Optional",
        "Union",
        "cast",
        "TYPE_CHECKING",
        "Final",
    }

    found = _guard("from typing import Any, ForwardRef\n")
    [imported] = [item for item in found if "the only imports are" in item]
    assert "`from typing import ForwardRef` is not permitted" in imported
    assert "Any" not in imported.split(" is not permitted")[0]
    assert any("`ForwardRef` is not permitted in the student file" in item for item in found)

    for name in ("get_type_hints", "get_args", "get_origin", "NewType", "TypeVar", "Protocol"):
        found = _guard(f"from typing import {name}\n")
        assert any(f"`from typing import {name}` is not permitted" in item for item in found), name


def test_an_annotation_string_handed_to_an_evaluator_is_rejected_before_it_runs() -> None:
    """`ForwardRef(...)._evaluate(...)` and `get_type_hints(...)` over a string are findings.

    The strings carry an `__import__` call that the name rules cannot see, because a string
    is not a name; the evaluators that would run them are refused by import and by name.
    """
    forward_ref = GUARDRAIL_ACCEPTED.replace(
        HEADER,
        HEADER + "\nfrom typing import ForwardRef\n\n"
        "MARKER = ForwardRef(\"__import__('os').getcwd()\")._evaluate({}, {}, frozenset())\n",
    )
    found = _guard(forward_ref)
    assert any("`from typing import ForwardRef` is not permitted" in item for item in found)
    assert _named(found, "ForwardRef") == [
        _line_of(forward_ref, "from typing import ForwardRef"),
        _line_of(forward_ref, "MARKER = "),
    ]
    assert _named(found, "_evaluate") == [_line_of(forward_ref, "MARKER = ")]
    assert "`__import__`" not in "".join(found)

    hints = GUARDRAIL_ACCEPTED.replace(
        HEADER,
        HEADER + "\nfrom typing import get_type_hints\n\n\n"
        "def probe(value: \"__import__('os').getcwd()\") -> None:\n"
        '    """Carry an annotation string."""\n\n\n'
        "HINTS = get_type_hints(probe)\n",
    )
    found = _guard(hints)
    assert any("`from typing import get_type_hints` is not permitted" in item for item in found)
    assert _named(found, "get_type_hints") == [
        _line_of(hints, "from typing import get_type_hints"),
        _line_of(hints, "HINTS = "),
    ]

    star = GUARDRAIL_ACCEPTED.replace(HEADER, HEADER + "\nfrom typing import *\n")
    assert any("`from typing import *` is not permitted" in item for item in _guard(star))


def test_pytest_is_used_only_as_fixture_decorator_mark_param_and_raises() -> None:
    """`pytest.fixture` assigned to a name is rejected, as is any other door."""
    accepted = HEADER + (
        "\n\n@pytest.mark.parametrize(\n"
        '    "response, state",\n'
        '    [pytest.param("valid", "COMPLETED", id="valid", marks=pytest.mark.asyncio),\n'
        '     pytest.param("malformed", "NEEDS_REVIEW", id="malformed")],\n'
        ")\n"
        "async def test_each(harness: InteractionHarness, response: str, state: str) -> None:\n"
        '    """One case per response."""\n'
        "    record = await harness.run_worker(response)\n"
        "    with pytest.raises(KeyError):\n"
        '        {}["summary"]\n'
        "    assert record.state == state\n"
    )
    assert _guard(accepted) == []

    for snippet, named in (
        ("fixture = pytest.fixture\n", "`pytest.fixture` is permitted only as a decorator"),
        ("skip = pytest.importorskip('os')\n", "`pytest.importorskip` is not permitted"),
        ("patcher = pytest.MonkeyPatch()\n", "`pytest.MonkeyPatch` is not permitted"),
        ("p = pytest\n", "`pytest` on its own is not permitted"),
        ("m = pytest.mark\n", "`pytest.mark` is not permitted"),
        (
            "@pytest.mark.skipif('mutated = True', reason='x')\ndef helper() -> None:\n"
            "    return None\n",
            "`pytest.mark.skipif` is not permitted",
        ),
        ("flag = pytest.param(1, marks=pytest.mark.xfail)\n", "`pytest.mark.xfail` is not"),
    ):
        source = HEADER + "\n" + snippet + GUARDRAIL_TEST
        found = _guard(source)
        assert len(found) == 1 and named in found[0], (snippet, found)


@pytest.mark.parametrize("shape", ["test", "fixture", "module helper", "nested function", "lambda"])
def test_a_reserved_parameter_name_is_rejected_on_every_kind_of_function(shape: str) -> None:
    """No function takes `request`, `monkeypatch`, `tmp_path`, or another built-in fixture name."""
    if shape == "test":
        source = GUARDRAIL_ACCEPTED.replace(
            SIGNATURE, '(harness: InteractionHarness, request) -> None:\n    """The record'
        )
        function = "test_one_response_is_stored"
    elif shape == "fixture":
        source = (
            HEADER
            + (
                "\n\n@pytest.fixture\ndef message(request) -> str:\n"
                '    """A fixture asking for pytest\'s request."""\n    return "x"\n'
            )
            + GUARDRAIL_TEST
        )
        function = "message"
    elif shape == "module helper":
        source = (
            HEADER
            + (
                "\n\ndef stored(request, expected) -> None:\n"
                '    """Assert one state."""\n'
                "    assert request.state == expected\n"
            )
            + GUARDRAIL_TEST.replace(STATE_ASSERT, "    stored(record, 'COMPLETED')\n")
        )
        function = "stored"
    elif shape == "nested function":
        source = HEADER + GUARDRAIL_TEST.replace(
            STATE_ASSERT,
            "    def check(request):\n"
            "        assert request.state == 'COMPLETED'\n\n"
            "    check(record)\n",
        )
        function = "check"
    else:
        source = GUARDRAIL_ACCEPTED.replace(
            STATE_ASSERT, "    name_of = lambda request: request.state\n" + STATE_ASSERT
        )
        function = "<lambda>"
    assert source != GUARDRAIL_ACCEPTED

    [finding] = _guard(source)
    assert finding == (
        f"line {_line_of(source, 'request')}: `request` is not permitted as a parameter of "
        f"`{function}`; {student_guard.RENAME_HINT}"
    )
    assert RENAME in finding


def test_every_reserved_fixture_name_is_rejected_as_a_test_parameter() -> None:
    """`monkeypatch`, `tmp_path`, `pytestconfig`, ... requested by a test are each named."""
    for fixture in sorted(student_guard.RESERVED_PARAMETERS):
        source = GUARDRAIL_ACCEPTED.replace(
            SIGNATURE, f'(harness: InteractionHarness, {fixture}) -> None:\n    """The record'
        )
        assert source != GUARDRAIL_ACCEPTED
        [finding] = _guard(source)
        assert f"`{fixture}` is not permitted as a parameter of" in finding, fixture
    assert _guard(GUARDRAIL_ACCEPTED) == []


def test_the_state_assertion_may_live_in_a_helper_fed_the_record() -> None:
    """A helper handed the record may hold the state assert; one handed a string may not."""
    helper = (
        "\n\ndef stored_state(stored, expected) -> None:\n"
        '    """Assert one state."""\n'
        "    assert stored.state == expected\n"
    )
    delegating = (
        HEADER
        + helper
        + GUARDRAIL_TEST.replace(STATE_ASSERT, "    stored_state(record, 'COMPLETED')\n")
    )
    assert _guard(delegating) == []

    misfed = delegating.replace(
        "    stored_state(record, 'COMPLETED')\n", "    stored_state('COMPLETED', record)\n"
    )
    [finding] = _guard(misfed)
    assert "has no `assert` comparing the `.state`" in finding

    # The record may arrive through a helper that returns what the worker returned.
    returned = HEADER + (
        "\n\nasync def _run(harness, response):\n"
        '    """Run one response."""\n'
        "    return await harness.run_worker(response)\n"
        "\n\nasync def test_valid(harness: InteractionHarness) -> None:\n"
        '    """A state."""\n'
        '    record = await _run(harness, "valid")\n'
        "    assert record.state == 'COMPLETED'\n"
    )
    assert _guard(returned) == []


def test_a_state_compared_on_something_the_test_built_itself_does_not_count() -> None:
    """`.state` of a value that did not come from the worker is not the stored state."""
    fake = GUARDRAIL_ACCEPTED.replace(
        STATE_ASSERT,
        "    class Fake:\n        state = 'COMPLETED'\n\n    assert Fake().state == 'COMPLETED'\n",
    )
    [finding] = _guard(fake)
    assert finding.startswith("`test_one_response_is_stored` has no `assert` comparing")

    unequal = GUARDRAIL_ACCEPTED.replace('record.state == "COMPLETED"', 'record.state != "FAILED"')
    assert _guard(unequal) == []


def test_an_audit_assertion_through_a_comprehension_or_a_helper_counts() -> None:
    """A list built from the trail, or a helper handed the text, carries the trail's provenance."""
    through_helper = HEADER + (
        "\n\ndef assert_clean(text, needle) -> None:\n"
        '    """Assert the needle is absent."""\n'
        "    assert needle not in text\n"
        "\n\nasync def test_clean(harness: InteractionHarness) -> None:\n"
        '    """No token."""\n'
        '    record = await harness.run_worker("valid")\n'
        '    secret = harness.token("dispatcher-valid")\n'
        "    assert_clean(harness.audit_text(record.exception_id), secret)\n"
    )
    assert _guard(through_helper, AUDIT) == []

    misfed = through_helper.replace(
        "assert_clean(harness.audit_text(record.exception_id), secret)",
        'assert_clean(secret, "x")',
    )
    [finding] = _guard(misfed, AUDIT)
    assert "has no `assert` over the audit trail" in finding


def test_methods_of_test_classes_are_collected_and_parametrized_tests_count_once() -> None:
    """`Test*` classes are walked; a parametrized test is one function with one verdict."""
    in_class = HEADER + (
        "\n\nclass TestGuardrail:\n"
        '    """Grouped."""\n\n'
        "    async def test_valid(self, harness: InteractionHarness) -> None:\n"
        '        """A summary, not a state."""\n'
        '        record = await harness.run_worker("valid")\n'
        "        assert record.summary is not None\n"
    )
    [finding] = _guard(in_class)
    assert finding.startswith("`TestGuardrail::test_valid` has no `assert` comparing")


def test_source_encoding_is_validated_and_a_syntax_error_is_a_finding() -> None:
    """Bytes are parsed under their declared encoding only when that encoding is UTF-8."""
    with_bom = b"\xef\xbb\xbf" + GUARDRAIL_ACCEPTED.encode("utf-8")
    assert _guard(with_bom) == []
    assert _guard(("# coding: utf-8\n" + GUARDRAIL_ACCEPTED).encode("utf-8")) == []

    [finding] = _guard(("# coding: unicode_escape\n" + GUARDRAIL_ACCEPTED).encode("utf-8"))
    assert finding.startswith(
        "tests/student/test_output_guardrail.py declares the source encoding 'unicode_escape'"
    )
    [finding] = _guard("def (:\n", AUDIT)
    assert finding.startswith("tests/student/test_audit.py is not valid Python: ")


def test_rules_are_chosen_by_file_name_and_other_files_are_refused(tmp_path: Path) -> None:
    """`findings(path)` applies the rules of the file's name; a foreign name is an error."""
    guardrail = tmp_path / "test_output_guardrail.py"
    guardrail.write_text(GUARDRAIL_ACCEPTED, encoding="utf-8")
    audit = tmp_path / "test_audit.py"
    audit.write_text(GUARDRAIL_ACCEPTED, encoding="utf-8")

    assert student_guard.findings(guardrail) == []
    [finding] = student_guard.findings(audit)
    assert "has no `assert` over the audit trail" in finding
    with pytest.raises(student_guard.StudentGuardError, match="not a student file"):
        student_guard.findings(tmp_path / "test_exception_access.py")
    with pytest.raises(student_guard.StudentGuardError, match="could not be read"):
        student_guard.findings(tmp_path / "missing" / "test_audit.py")


def test_main_checks_both_files_and_reports_findings_and_unreadable_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 0 when both are clean, 1 with findings in either, 2 when a file cannot be read."""
    guardrail = tmp_path / "test_output_guardrail.py"
    audit = tmp_path / "test_audit.py"
    guardrail.write_text(GUARDRAIL_ACCEPTED, encoding="utf-8")
    audit.write_text(AUDIT_ACCEPTED, encoding="utf-8")
    assert student_guard.main([str(guardrail), str(audit)]) == 0
    out = capsys.readouterr().out
    assert "tests/student/test_output_guardrail.py uses only the supplied harness" in out
    assert "tests/student/test_audit.py uses only the supplied harness" in out

    guardrail.write_text(_file_counterexample(), encoding="utf-8")
    assert student_guard.main([str(guardrail), str(audit)]) == 1
    captured = capsys.readouterr()
    assert "tests/student/test_output_guardrail.py will not be run" in captured.err
    assert "tests/student/test_audit.py uses only the supplied harness" in captured.out

    assert student_guard.main([str(tmp_path / "absent" / "test_audit.py")]) == 2


def test_the_rule_sets_hold_the_reviews_lists() -> None:
    """The names the reviews required are all in the sets, and the import set is the four forms."""
    required_names = {
        "__file__",
        "__import__",
        "__builtins__",
        "importlib",
        "inspect",
        "sys",
        "os",
        "subprocess",
        "builtins",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "eval",
        "exec",
        "compile",
        "open",
        "Path",
        # Review round 1 of Task 4.3: the annotation evaluators.
        "typing",
        "ForwardRef",
        "get_type_hints",
        # Review round 2 of Task 4.3: format-field traversal.
        "format",
        "format_map",
    }
    assert required_names <= student_guard.FORBIDDEN_NAMES
    assert {"format", "format_map"} <= student_guard.ATTRIBUTE_ONLY_NAMES
    required_parameters = {
        "request",
        "monkeypatch",
        "pytestconfig",
        "capsys",
        "capfd",
        "caplog",
        "tmp_path",
        "tmp_path_factory",
        "recwarn",
    }
    assert required_parameters <= student_guard.RESERVED_PARAMETERS
    assert not required_parameters & student_guard.FORBIDDEN_NAMES
    assert not student_guard.TYPING_NAMES & student_guard.FORBIDDEN_NAMES
    assert student_guard.HARNESS_NAMES == {"InteractionHarness"}
    assert student_guard.HARNESS_MODULE == "tests.security.interaction"
    assert student_guard.PYTEST_CALLS == {"param", "raises"}
    assert set(student_guard.STUDENT_FILES) == {"test_output_guardrail.py", "test_audit.py"}
    assert GUARDRAIL.sources == {"run_worker"} and GUARDRAIL.required_attribute == "state"
    assert AUDIT.sources == {"audit_trail", "audit_text"} and AUDIT.required_attribute is None


def _poe_tasks() -> dict[str, object]:
    """Return the layer's Poe task table."""
    tasks = tomllib.loads((TASK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "poe"
    ]["tasks"]
    assert isinstance(tasks, dict)
    return tasks


def test_verify_runs_the_student_guard_right_after_the_snapshot_and_before_student_tests() -> None:
    """`poe student-guard` precedes `unit`, the assessed steps, and `student-tests` in `verify`.

    `poe student-tests` is itself a sequence that runs the guard before the bare pytest run,
    and the two assessed steps go through the assessed-module runner.
    """
    tasks = _poe_tasks()
    verify = tasks["verify"]
    assert isinstance(verify, list)

    assert tasks["student-guard"] == "python -m tests.security.student_guard"
    assert tasks["guardrail-binding"] == "python -m tests.security.guardrail_binding"
    assert verify.index("student-guard") == verify.index("integrity-record") + 1
    assert verify.index("student-guard") < verify.index("unit")
    assert verify.index("output-contract") < verify.index("e2e")
    assert verify.index("output-contract") < verify.index("negative-tests-contract")
    assert verify.index("negative-tests-contract") < verify.index("student-tests")
    assert verify.index("student-tests") < verify.index("submission")
    assert verify[-1] == "integrity-check"
    assert verify.count("student-guard") == 1
    assert "route-guard" not in verify and "access-contract" not in verify
    assert tasks["student-tests"] == ["student-guard", "student-tests-run"]
    assert tasks["student-tests-run"] == "pytest tests/student"
    assert tasks["e2e"] == ["ingest", "e2e-tests"]
    runner = "python -m tests.security.assessed_run"
    assert tasks["output-contract"] == f"{runner} tests/contract/test_output_audit.py"
    assert tasks["negative-tests-contract"] == f"{runner} tests/contract/test_negative_tests.py"


def test_poe_student_tests_runs_the_guard_before_pytest_collects_a_rejected_file(
    tmp_path: Path,
) -> None:
    """`poe student-tests` must not import a rejected file.

    A student file that writes a marker at import time, and that the guard rejects (it
    imports `pathlib` and reads `__file__`), is placed in a scratch project with the real
    `student-guard`, `student-tests-run`, and `student-tests` task definitions, beside an
    empty second student file. Through `poe student-tests` the guard fails first, the
    sequence stops, and the marker is never written. Through the bare `poe student-tests-run`
    the same file is imported and the marker appears, which is exactly what the guard in
    front of it prevents.
    """
    tasks = _poe_tasks()
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poe.tasks]\n"
        f'student-guard = "{tasks["student-guard"]}"\n'
        f'student-tests-run = "{tasks["student-tests-run"]}"\n'
        f"student-tests = {json.dumps(tasks['student-tests'])}\n",
        encoding="utf-8",
    )
    security = tmp_path / "tests/security"
    security.mkdir(parents=True)
    shutil.copy(TASK_ROOT / "tests/security/student_guard.py", security / "student_guard.py")
    student = tmp_path / "tests/student"
    student.mkdir()
    (student / "test_audit.py").write_text("", encoding="utf-8")
    marker = student / "imported.marker"
    rejected = student / "test_output_guardrail.py"
    rejected.write_text(
        '"""Rejected: it reads its environment when imported."""\n\n'
        "from pathlib import Path\n\n"
        f'Path(__file__).with_name("{marker.name}").write_text("the module ran", '
        'encoding="utf-8")\n',
        encoding="utf-8",
    )
    assert any("`__file__` is not permitted" in item for item in student_guard.findings(rejected))

    # Poe resolves `python` and `pytest` on PATH; the interpreter running this test and its
    # scripts directory go first, as `uv run` puts the project environment first.
    environment = {
        **os.environ,
        "PATH": os.pathsep.join(
            [
                str(Path(sys.executable).parent),
                sysconfig.get_path("scripts"),
                os.environ.get("PATH", ""),
            ]
        ),
    }

    def poe(task: str) -> str:
        completed = subprocess.run(
            [sys.executable, "-m", "poethepoet", task],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        return f"exit {completed.returncode}\n{completed.stdout}{completed.stderr}"

    guarded = poe("student-tests")
    assert not guarded.startswith("exit 0"), guarded
    assert "student-guard: tests/student/test_output_guardrail.py will not be run" in guarded
    assert "`__file__` is not permitted" in guarded
    assert "test session starts" not in guarded, guarded
    assert not marker.exists(), "poe student-tests imported the rejected file"

    bare = poe("student-tests-run")
    assert "test session starts" in bare, bare
    assert marker.read_text(encoding="utf-8") == "the module ran"
