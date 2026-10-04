"""Coldline.

===================

File:              tests/security/student_guard.py
Component:         Security tooling — Static student-test guard
Purpose:           Check, without importing them, that tests/student/test_output_guardrail.py and
                    tests/student/test_audit.py use only the supplied harness and assert what
                    each file owes, before any step executes them.
Interacts With:    tests/student/test_output_guardrail.py, tests/student/test_audit.py,
                    tests/security/guardrail_mutation.py, pyproject.toml (`poe student-guard`,
                    `poe student-tests`, `poe verify`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Trusted static analysis before untrusted code runs, closed import set,
                    flat name rules, assertions over outcomes
Tools:             Python 3.12, ast, tokenize

The student's test files are Python that ``poe verify`` executes several times: once as
written for the executed-case inventory, once per mutation, and once more in
``student-tests``. A test that inspected its own environment instead of the outcome could
tell a mutated run from a plain one without asserting anything about the worker or the
API (the mutated copy of ``src/`` sits at another path, and ``worker.use_cases.__file__``
would say so), and would then pass every mutation verdict while proving nothing. This guard
runs **before any execution of either file**: ``guardrail_mutation.py`` refuses to run a
file it rejects, ``poe student-guard`` is a step of ``poe verify`` ahead of ``unit`` and
``student-tests``, and ``poe student-tests`` is itself a sequence that runs this guard before
pytest collects anything (the bare pytest run is ``poe student-tests-run``).

The rules are Task 4.2's five flat rules, unchanged in substance: a name on a list is
rejected wherever it appears, with no exemption for a binding the file makes itself, and
only syntactic presence is checked here; the mutations check behavior. What Task 4.3
changes is the targeting (two files, one harness class) and rule 5, the assertion each
file owes:

1. **Forbidden names.** ``__file__``, ``__import__``, ``__builtins__``, ``importlib``,
   ``inspect``, ``sys``, ``os``, ``subprocess``, ``builtins``, ``globals``, ``locals``,
   ``vars``, ``getattr``, ``setattr``, ``delattr``, ``eval``, ``exec``, ``compile``, ``open``
   and ``Path`` are rejected wherever they appear: as a name in any context (a read, an
   assignment, ``for``, ``with`` or comprehension target, a parameter, an import alias, a
   function or class name) and as the attribute of any ``x.<name>``. Every dunder
   (``x.__class__``, ``__spec__``) is rejected the same way, and so are the frame, code and
   traceback attributes and the harness's own internals (its path, store and sink handles)
   that reach the same places (the rest of ``FORBIDDEN_NAMES``). ``x.format`` and
   ``x.format_map`` are rejected as attributes (review round 2): a format field inside a
   string constant (``"{0.run_worker.__func__.__globals__}".format(harness)``) traverses
   attributes the name rules cannot see, and taking the bound method under another name
   (``render = template.format``) is the same attribute access. An f-string stays
   permitted: its expressions are AST the rules inspect.
2. **Imports.** Exactly ``import pytest``, ``from __future__ import annotations``,
   ``from typing import <name>`` for a name on the short allowlist ``TYPING_NAMES``
   (``Any``, ``Annotated``, ``Literal``, ``Optional``, ``Union``, ``cast``,
   ``TYPE_CHECKING``, ``Final``: annotation vocabulary that evaluates nothing) and
   ``from tests.security.interaction import InteractionHarness``. Everything else is
   rejected, ``from pytest import ...``, ``import typing``, ``from typing import *`` and
   every other ``typing`` name included: ``ForwardRef`` and ``get_type_hints`` evaluate
   annotation strings, which is code execution the name rules cannot see, so they and any
   other ``typing`` attribute are refused by name. ``as`` is rejected except on a
   permitted ``typing`` name.
3. **Pytest.** ``pytest`` is used only as ``@pytest.fixture`` (bare or called, directly in a
   decorator list), ``pytest.mark.<name>``, ``pytest.param`` and ``pytest.raises``. Any other
   ``pytest.<attribute>``, ``pytest.fixture`` anywhere but a decorator, and ``pytest`` on its
   own (``p = pytest``) are rejected.
4. **Reserved parameter names.** A parameter of any function (a test, a fixture, a helper,
   a nested function, a lambda) named ``request``, ``monkeypatch``, ``pytestconfig``,
   ``capsys``, ``capfd``, ``caplog``, ``tmp_path``, ``tmp_path_factory``, ``recwarn`` or
   another pytest built-in fixture in ``RESERVED_PARAMETERS`` is rejected, with the advice
   to rename it, for example to ``resp``. A local variable of that name is an ordinary
   variable (``request = f"/api/v1/exceptions/{exception_id}"``).
5. **Assertions.** Every collected test (module-level ``test*`` functions and ``test*``
   methods of ``Test*`` classes) asserts, itself, in a function nested in it, or in a
   module-level helper it calls, over a value obtained from the harness:
   - in ``test_output_guardrail.py``, a comparison of the ``.state`` of a record obtained
     from ``harness.run_worker(...)`` (a name bound from it, or the result of a helper that
     returns one);
   - in ``test_audit.py``, an assertion over the audit trail: a value obtained from
     ``harness.audit_trail(...)`` or ``harness.audit_text(...)``, a name bound from one, or
     the result of a helper that returns one.
   Provenance into a helper or nested function is per parameter and per call, so an assert
   in another helper over a parameter that happens to share the name counts for nothing.

Each file is read as bytes and its source encoding validated (UTF-8 only, a BOM or a
``coding: utf-8`` line allowed); the file is never imported.
``python -m tests.security.student_guard`` (``poe student-guard``) checks both files,
prints the findings, and exits 1 when there is one.
"""

from __future__ import annotations

import argparse
import ast
import codecs
import io
import sys
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
PYTEST = "pytest"
FUTURE = "__future__"
FUTURE_FEATURE = "annotations"
TYPING = "typing"
# The `typing` names a student file may import: annotation vocabulary only. Nothing on
# this list evaluates a string or reaches a module; `ForwardRef`, `get_type_hints`,
# `get_args`, `NewType` and the rest of the module are refused with every other name.
TYPING_NAMES: frozenset[str] = frozenset(
    {"Any", "Annotated", "Literal", "Optional", "Union", "cast", "TYPE_CHECKING", "Final"}
)
HARNESS_MODULE = "tests.security.interaction"
# What a student file may take from the harness module: the harness class, and nothing
# the module itself imported (the emulator, the worker application, yaml, the trace writer).
HARNESS_NAMES: frozenset[str] = frozenset({"InteractionHarness"})
STATE_ATTRIBUTE = "state"


@dataclass(frozen=True)
class FileRules:
    """What one student file may import and what each of its tests must assert.

    ``sources`` are the harness attributes whose results count as "obtained from the
    harness" for rule 5; ``required_attribute`` is the attribute an assert must compare on
    such a value (``state``), or None when any assert over such a value satisfies the rule.
    """

    path: Path
    sources: frozenset[str]
    required_attribute: str | None
    assertion_hint: str


STUDENT_FILES: dict[str, FileRules] = {
    "test_output_guardrail.py": FileRules(
        path=Path("tests/student/test_output_guardrail.py"),
        sources=frozenset({"run_worker"}),
        required_attribute=STATE_ATTRIBUTE,
        assertion_hint=(
            "has no `assert` comparing the `.state` of a record obtained from "
            "`harness.run_worker(...)`: assert the stored state of the record the worker left"
        ),
    ),
    "test_audit.py": FileRules(
        path=Path("tests/student/test_audit.py"),
        sources=frozenset({"audit_trail", "audit_text"}),
        required_attribute=None,
        assertion_hint=(
            "has no `assert` over the audit trail: assert over `harness.audit_trail(...)` or "
            "`harness.audit_text(...)`, or a value bound from one"
        ),
    ),
}
STUDENT_PATHS: tuple[Path, ...] = tuple(rules.path for rules in STUDENT_FILES.values())
# Names and attributes that inspect or escape the test's environment rather than describe
# an outcome, rejected wherever they appear. The first group is the review's list; the rest
# reach the same places: frames, code objects and tracebacks, and the handles the harness
# holds (its path, its store, its sink, its emulator) and the file methods a leaked path
# would offer.
FORBIDDEN_NAMES: frozenset[str] = frozenset(
    {
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
        # The same places by other doors.
        "breakpoint",
        "input",
        "traceback",
        # Annotation evaluators: a string handed to one of these is code.
        "typing",
        "ForwardRef",
        "get_type_hints",
        "evaluate_forward_ref",
        "_evaluate",
        "getrepr",
        "tb_frame",
        "tb_next",
        "f_code",
        "f_globals",
        "f_locals",
        "f_back",
        "co_filename",
        "gi_frame",
        "cr_frame",
        "ag_frame",
        # Format fields traverse attributes inside a string constant (review round 2).
        "format",
        "format_map",
        # The harness's own handles, and what a path would offer.
        "root",
        "_fixtures",
        "_trace",
        "_audit",
        "_audit_store",
        "_planted",
        "_emulator",
        "repository",
        "records",
        "append",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "iterdir",
        "glob",
        "rglob",
    }
)
# Names that only reach a path, a frame, a format-field traversal, or a harness internal
# as an attribute (`harness.root`, `p.read_text`, `tb.tb_frame`, `harness.repository`,
# `template.format`). They are findings only in attribute position: a local variable the
# file binds itself under one of these names (`records = harness.audit_trail(exception_id)`)
# reaches nothing, and the builtin `format(value, spec)` traverses nothing.
ATTRIBUTE_ONLY_NAMES: frozenset[str] = frozenset(
    {
        "format",
        "format_map",
        "root",
        "_fixtures",
        "_trace",
        "_audit",
        "_audit_store",
        "_planted",
        "_emulator",
        "repository",
        "records",
        "append",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "iterdir",
        "glob",
        "rglob",
        "getrepr",
        "tb_frame",
        "tb_next",
        "f_code",
        "f_globals",
        "f_locals",
        "f_back",
        "co_filename",
        "gi_frame",
        "cr_frame",
        "ag_frame",
    }
)
# pytest fills a parameter of these names with a built-in fixture that reaches the
# configuration, the filesystem, the capture machinery or the fixture registry. The first
# group is the review's list; the rest are the other built-in fixtures with such reach.
RESERVED_PARAMETERS: frozenset[str] = frozenset(
    {
        "request",
        "monkeypatch",
        "pytestconfig",
        "capsys",
        "capfd",
        "caplog",
        "tmp_path",
        "tmp_path_factory",
        "recwarn",
        # The rest of pytest's built-in fixtures with the same reach.
        "tmpdir",
        "tmpdir_factory",
        "cache",
        "capsysbinary",
        "capfdbinary",
        "pytester",
        "testdir",
        "doctest_namespace",
        "record_property",
        "record_xml_attribute",
        "record_testsuite_property",
    }
)
PYTEST_MARK = "mark"
PYTEST_FIXTURE = "fixture"
PYTEST_CALLS: frozenset[str] = frozenset({"param", "raises"})
# `skipif` and `xfail` evaluate strings and change outcomes; no other mark is needed.
PERMITTED_MARKS: frozenset[str] = frozenset({"asyncio", "parametrize"})
TEST_PREFIX = "test"
CLASS_PREFIX = "Test"
PERMITTED_ENCODINGS: frozenset[str] = frozenset({"utf-8", "utf-8-sig"})
IMPORT_HINT = (
    "the only imports are `import pytest`, `from __future__ import annotations`, "
    "`from typing import <name>` for Any, Annotated, Literal, Optional, Union, cast, "
    "TYPE_CHECKING or Final, and `from tests.security.interaction import "
    "InteractionHarness` (`as` only on one of those typing names)"
)
NAME_HINT = (
    "the tests describe outcomes only; reading the environment, the filesystem, or a "
    "module's internals is not permitted, and a name on this list is rejected wherever "
    "it appears"
)
PYTEST_HINT = (
    "`pytest` is used only as `@pytest.fixture`, `pytest.mark.<name>`, `pytest.param`, "
    "and `pytest.raises`"
)
RENAME_HINT = "pytest reserves this name for a built-in fixture; rename it, for example to `resp`"

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
ScopeNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


class StudentGuardError(ValueError):
    """Report that a student file could not be read, as opposed to a finding about it."""


def rules_for(path: Path) -> FileRules:
    """Return the rules for one student file, by its name, or raise for any other file."""
    rules = STUDENT_FILES.get(path.name)
    if rules is None:
        names = ", ".join(STUDENT_FILES)
        raise StudentGuardError(f"{path.name} is not a student file of this Task ({names})")
    return rules


@dataclass
class _Collected:
    """Hold what the module defines: its tests, by qualified name, and its helpers."""

    tests: list[tuple[str, FunctionNode]] = field(default_factory=list)
    helpers: dict[str, FunctionNode] = field(default_factory=dict)


@dataclass
class _Flow:
    """What one function's names hold, for the assertion rule.

    ``derived`` names hold a value obtained from the harness's sources (a record from
    ``run_worker``, a trail from ``audit_trail``, anything bound from one); the flag says
    whether the function returns such a value, so a call to it is such a value too.
    """

    derived: set[str] = field(default_factory=set)
    returns_derived: bool = False

    def snapshot(self) -> tuple[frozenset[str], bool]:
        """Return the state, for the fixpoint's change detection."""
        return (frozenset(self.derived), self.returns_derived)


def encoding_findings(source: bytes, path: Path) -> list[str]:
    """Return why the file's source encoding is not UTF-8, detected as the interpreter does."""
    try:
        declared, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
    except SyntaxError as exc:
        return [f"{path.as_posix()} declares an unusable source encoding: {exc}"]
    try:
        name = codecs.lookup(declared).name
    except LookupError:
        name = declared
    if name not in PERMITTED_ENCODINGS:
        return [
            f"{path.as_posix()} declares the source encoding {declared!r}; only "
            "UTF-8 is permitted (remove the `coding` declaration)"
        ]
    return []


def _parse(source: str | bytes, path: Path) -> tuple[ast.Module | None, list[str]]:
    """Parse a student file, validating a byte source's encoding first; or say why not."""
    if isinstance(source, bytes):
        rejected = encoding_findings(source, path)
        if rejected:
            return None, rejected
    try:
        return ast.parse(source), []
    except SyntaxError as exc:
        return None, [f"{path.as_posix()} is not valid Python: {exc}"]
    except ValueError as exc:
        return None, [f"{path.as_posix()} could not be decoded as UTF-8: {exc}"]


def _line(node: ast.AST) -> str:
    """Return ``line N`` for a node, for a finding."""
    return f"line {getattr(node, 'lineno', '?')}"


def _is_dunder(name: str) -> bool:
    """Return whether ``name`` is a dunder (``__file__``), which is rejected wherever it appears."""
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _parameters(arguments: ast.arguments) -> list[ast.arg]:
    """Return every parameter of a signature, in order, ``*args`` and ``**kwargs`` included."""
    parameters = [*arguments.posonlyargs, *arguments.args]
    if arguments.vararg is not None:
        parameters.append(arguments.vararg)
    parameters.extend(arguments.kwonlyargs)
    if arguments.kwarg is not None:
        parameters.append(arguments.kwarg)
    return parameters


def _function_name(scope: ScopeNode) -> str:
    """Return a function's name, or ``<lambda>``."""
    return scope.name if isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef) else "<lambda>"


def _own_nodes(function: FunctionNode) -> list[ast.AST]:
    """Return the nodes of a function's own body; a nested function or lambda is listed, not opened.

    The nested function's body belongs to that function, which the caller analyses on its own.
    """
    stack: list[ast.AST] = list(reversed(function.body))
    nodes: list[ast.AST] = []
    while stack:
        node = stack.pop()
        nodes.append(node)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return nodes


# --- Rule 1: forbidden names, wherever they appear ---------------------------------------


def forbidden_name_findings(tree: ast.Module) -> list[str]:
    """Return one finding per forbidden or dunder name, by line, in every position it can hold.

    A name in ``FORBIDDEN_NAMES`` or any dunder is a finding as an ``ast.Name`` in any
    context, as the attribute of an ``ast.Attribute``, as a parameter, as an import alias
    (the imported name or its ``as`` name), as a function, class or exception-handler name,
    in a ``global`` or ``nonlocal`` statement, and as a match-pattern capture. No binding
    exempts it.
    """
    seen: set[tuple[int, str]] = set()
    findings: list[str] = []

    def check(node: ast.AST, name: str) -> None:
        if name not in FORBIDDEN_NAMES and not _is_dunder(name):
            return
        if name in ATTRIBUTE_ONLY_NAMES and not isinstance(node, ast.Attribute):
            return
        key = (getattr(node, "lineno", 0), name)
        if key not in seen:
            seen.add(key)
            findings.append(
                f"{_line(node)}: `{name}` is not permitted in the student file; {NAME_HINT}"
            )

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            check(node, node.id)
        elif isinstance(node, ast.Attribute):
            check(node, node.attr)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                check(node, node.name)
            for parameter in _parameters(node.args):
                check(parameter, parameter.arg)
        elif isinstance(node, ast.ClassDef):
            check(node, node.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                check(alias, alias.name)
                if alias.asname is not None:
                    check(alias, alias.asname)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    check(alias, alias.asname)
        elif isinstance(node, ast.ExceptHandler) and node.name is not None:
            check(node, node.name)
        elif isinstance(node, ast.Global | ast.Nonlocal):
            for name in node.names:
                check(node, name)
        elif isinstance(node, ast.MatchAs | ast.MatchStar) and node.name is not None:
            check(node, node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest is not None:
            check(node, node.rest)
    return findings


# --- Rule 2: the closed import set --------------------------------------------------------


def import_findings(tree: ast.Module) -> list[str]:
    """Return one finding per import outside the four permitted forms, wherever it appears."""
    findings: list[str] = []

    def reject(node: ast.AST, statement: str) -> None:
        findings.append(f"{_line(node)}: `{statement}` is not permitted; {IMPORT_HINT}")

    def spelled(alias: ast.alias) -> str:
        return alias.name if alias.asname is None else f"{alias.name} as {alias.asname}"

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name != PYTEST or alias.asname is not None:
                    reject(node, f"import {spelled(alias)}")
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                if node.level:
                    permitted = False
                elif module == FUTURE:
                    permitted = alias.name == FUTURE_FEATURE and alias.asname is None
                elif module == TYPING:
                    # A star import and every name outside the allowlist are refused:
                    # `ForwardRef` and `get_type_hints` evaluate annotation strings.
                    permitted = alias.name in TYPING_NAMES
                elif module == HARNESS_MODULE:
                    permitted = alias.name in HARNESS_NAMES and alias.asname is None
                else:
                    permitted = False
                if not permitted:
                    reject(node, f"from {module} import {spelled(alias)}")
    return findings


# --- Rule 3: how pytest may be used --------------------------------------------------------


def _attribute_chain(node: ast.Attribute) -> tuple[ast.Name | None, list[str]]:
    """Return the root name and the dotted parts of ``a.b.c``, or no root when it is not a name."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        return current, [current.id, *reversed(parts)]
    return None, []


def pytest_findings(tree: ast.Module) -> list[str]:
    """Return one finding per use of ``pytest`` beyond fixture decorators, marks, param, raises."""
    findings: list[str] = []
    decorator_targets: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                decorator_targets.add(id(target))

    inner = {id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    consumed: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        root, chain = _attribute_chain(node)
        if root is None or chain[0] != PYTEST:
            continue
        consumed.add(id(root))
        dotted = ".".join(chain)
        if chain[1:] == [PYTEST_MARK] and id(node) in inner:
            continue
        if len(chain) == 3 and chain[1] == PYTEST_MARK:
            if chain[2] not in PERMITTED_MARKS:
                findings.append(
                    f"{_line(node)}: `{dotted}` is not permitted; only "
                    f"`pytest.mark.asyncio` and `pytest.mark.parametrize` are; {PYTEST_HINT}"
                )
            continue
        if len(chain) == 2 and chain[1] in PYTEST_CALLS:
            continue
        if chain[1:] == [PYTEST_FIXTURE]:
            if id(node) not in decorator_targets:
                findings.append(
                    f"{_line(node)}: `pytest.fixture` is permitted only as a decorator "
                    "(`@pytest.fixture` or `@pytest.fixture(...)`), not assigned, passed, or "
                    f"called elsewhere; {PYTEST_HINT}"
                )
            continue
        findings.append(f"{_line(node)}: `{dotted}` is not permitted; {PYTEST_HINT}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == PYTEST and id(node) not in consumed:
            findings.append(
                f"{_line(node)}: `pytest` on its own is not permitted (only as "
                f"`pytest.<attribute>`); {PYTEST_HINT}"
            )
    return findings


# --- Rule 4: reserved parameter names -----------------------------------------------------


def parameter_findings(tree: ast.Module) -> list[str]:
    """Return one finding per parameter, of any function, that names a pytest built-in fixture."""
    findings: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        for parameter in _parameters(node.args):
            if parameter.arg in RESERVED_PARAMETERS:
                findings.append(
                    f"{_line(parameter)}: `{parameter.arg}` is not permitted as a parameter of "
                    f"`{_function_name(node)}`; {RENAME_HINT}"
                )
    return findings


# --- Rule 5: assertions over what the harness returned --------------------------------------


def _collect(tree: ast.Module) -> _Collected:
    """Return the collected test functions (module-level and in Test classes) and the helpers."""
    collected = _Collected()

    def visit(body: list[ast.stmt], prefix: str, in_class: bool) -> None:
        for node in body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                if node.name.startswith(TEST_PREFIX):
                    collected.tests.append((f"{prefix}{node.name}", node))
                elif not in_class:
                    collected.helpers[node.name] = node
            elif isinstance(node, ast.ClassDef) and node.name.startswith(CLASS_PREFIX):
                visit(node.body, f"{prefix}{node.name}::", True)

    visit(tree.body, "", False)
    return collected


def _nested_functions(function: FunctionNode) -> list[FunctionNode]:
    """Return the functions defined directly inside this one (not those inside those)."""
    return [
        node
        for node in _own_nodes(function)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]


def _bound(node: ast.AST) -> tuple[list[ast.expr], ast.expr | None]:
    """Return a binding node's targets and the expression they are bound from, or nothing."""
    if isinstance(node, ast.Assign):
        return node.targets, node.value
    if isinstance(node, ast.AnnAssign | ast.AugAssign) and node.value is not None:
        return [node.target], node.value
    if isinstance(node, ast.NamedExpr):
        return [node.target], node.value
    if isinstance(node, ast.withitem) and node.optional_vars is not None:
        return [node.optional_vars], node.context_expr
    if isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
        return [node.target], node.iter
    return [], None


def _arguments_to_parameters(call: ast.Call, callee: FunctionNode) -> list[tuple[str, ast.expr]]:
    """Return which parameter of ``callee`` each argument of ``call`` binds.

    Positional arguments bind positional parameters in order (``*args`` after them), and
    keyword arguments bind the parameter of that name (``**kwargs`` otherwise). A starred
    argument may reach any positional parameter from its position on, and ``*args``, so it
    binds all of them: a record unpacked into a helper still gives its assert provenance.
    """
    arguments = callee.args
    positional = [*arguments.posonlyargs, *arguments.args]
    named = {parameter.arg for parameter in [*positional, *arguments.kwonlyargs]}
    pairs: list[tuple[str, ast.expr]] = []
    for index, argument in enumerate(call.args):
        if isinstance(argument, ast.Starred):
            pairs.extend((parameter.arg, argument.value) for parameter in positional[index:])
            if arguments.vararg is not None:
                pairs.append((arguments.vararg.arg, argument.value))
            continue
        if index < len(positional):
            pairs.append((positional[index].arg, argument))
        elif arguments.vararg is not None:
            pairs.append((arguments.vararg.arg, argument))
    for keyword in call.keywords:
        if keyword.arg is None:
            continue
        if keyword.arg in named:
            pairs.append((keyword.arg, keyword.value))
        elif arguments.kwarg is not None:
            pairs.append((arguments.kwarg.arg, keyword.value))
    return pairs


class _Reach:
    """A test with the functions its assertions may live in, and what their names hold.

    The set is the test, every function nested in it (and in those), and every
    module-level helper any of them calls by name, transitively. Each has its own
    ``_Flow``; a nested function also sees its enclosing function's names, a helper sees
    only what its call sites hand it.
    """

    def __init__(
        self, test: FunctionNode, helpers: dict[str, FunctionNode], sources: frozenset[str]
    ) -> None:
        """Walk the calls from ``test`` outward and run the provenance fixpoint."""
        self.sources = sources
        self.functions: list[FunctionNode] = []
        self.callables: dict[str, FunctionNode] = dict(helpers)
        self.enclosing: dict[FunctionNode, FunctionNode] = {}
        self.flows: dict[FunctionNode, _Flow] = {}
        queue: list[FunctionNode] = []

        def add(function: FunctionNode) -> None:
            if function in self.flows:
                return
            self.functions.append(function)
            self.flows[function] = _Flow()
            queue.append(function)
            for nested in _nested_functions(function):
                self.callables[nested.name] = nested
                self.enclosing[nested] = function
                add(nested)

        add(test)
        while queue:
            current = queue.pop()
            for node in _own_nodes(current):
                callee = self._callee(node)
                if callee is not None:
                    add(callee)
        self._settle()

    def _callee(self, node: ast.AST) -> FunctionNode | None:
        """Return the function in the set a call by name reaches, if any."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return self.callables.get(node.func.id)
        return None

    def derived(self, expression: ast.AST, flow: _Flow) -> bool:
        """Return whether the expression holds a value obtained from a harness source."""
        for node in ast.walk(expression):
            if isinstance(node, ast.Name) and node.id in flow.derived:
                return True
            if isinstance(node, ast.Attribute) and node.attr in self.sources:
                return True
            callee = self._callee(node)
            if callee is not None and callee in self.flows and self.flows[callee].returns_derived:
                return True
        return False

    def _settle(self) -> None:
        """Propagate provenance through bindings, call sites and returns until nothing changes."""
        while True:
            before = [self.flows[function].snapshot() for function in self.functions]
            for function in self.functions:
                self._propagate(function)
            if [self.flows[function].snapshot() for function in self.functions] == before:
                return

    def _propagate(self, function: FunctionNode) -> None:
        """Run one pass over a function's own nodes."""
        flow = self.flows[function]
        parent = self.enclosing.get(function)
        if parent is not None:
            flow.derived |= self.flows[parent].derived
        for node in _own_nodes(function):
            targets, value = _bound(node)
            if value is not None and self.derived(value, flow):
                flow.derived.update(
                    leaf.id
                    for target in targets
                    for leaf in ast.walk(target)
                    if isinstance(leaf, ast.Name)
                )
            callee = self._callee(node)
            if callee is not None and isinstance(node, ast.Call):
                for parameter, argument in _arguments_to_parameters(node, callee):
                    if self.derived(argument, flow):
                        self.flows[callee].derived.add(parameter)
            if isinstance(node, ast.Return) and node.value is not None:
                if self.derived(node.value, flow):
                    flow.returns_derived = True

    def compares_attribute(self, assertion: ast.Assert, flow: _Flow, attribute: str) -> bool:
        """Return whether the assert compares ``.<attribute>`` of a value from the sources."""
        for node in ast.walk(assertion.test):
            if not isinstance(node, ast.Compare):
                continue
            for part in ast.walk(node):
                if (
                    isinstance(part, ast.Attribute)
                    and part.attr == attribute
                    and self.derived(part.value, flow)
                ):
                    return True
        return False

    def asserts(self) -> list[tuple[ast.Assert, _Flow]]:
        """Return every assert in the set, with the flow of the function holding it."""
        return [
            (node, self.flows[function])
            for function in self.functions
            for node in _own_nodes(function)
            if isinstance(node, ast.Assert)
        ]


def assertion_findings(tree: ast.Module, rules: FileRules) -> list[str]:
    """Return which collected tests lack the assertion the file owes."""
    collected = _collect(tree)
    findings: list[str] = []
    for qualified, function in collected.tests:
        reach = _Reach(function, collected.helpers, rules.sources)
        asserts = reach.asserts()
        if rules.required_attribute is not None:
            satisfied = any(
                reach.compares_attribute(assertion, flow, rules.required_attribute)
                for assertion, flow in asserts
            )
        else:
            satisfied = any(reach.derived(assertion.test, flow) for assertion, flow in asserts)
        if not satisfied:
            findings.append(f"`{qualified}` {rules.assertion_hint}")
    return findings


def findings_for_source(source: str | bytes, rules: FileRules) -> list[str]:
    """Return every reason the student file must not be executed, or an empty list.

    Bytes are what the file holds and are parsed as such after their encoding is validated;
    a string is already-decoded text, for callers that build files in memory.
    """
    tree, findings = _parse(source, rules.path)
    if tree is None:
        return findings
    return (
        import_findings(tree)
        + forbidden_name_findings(tree)
        + pytest_findings(tree)
        + parameter_findings(tree)
        + assertion_findings(tree, rules)
    )


def read_source(path: Path) -> bytes:
    """Return a student file's bytes, or raise ``StudentGuardError`` if it cannot be read."""
    try:
        return path.read_bytes()
    except OSError as exc:
        raise StudentGuardError(f"{path.as_posix()} could not be read: {exc}") from exc


def findings(path: Path) -> list[str]:
    """Return the findings for the student file at ``path``, read as bytes, under its rules."""
    rules = rules_for(path)
    return findings_for_source(read_source(path), rules)


def main(argv: list[str] | None = None) -> int:
    """Check the student files (both by default) and print the findings."""
    parser = argparse.ArgumentParser(
        description="Check the student test files before anything runs them."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[TASK_ROOT / path for path in STUDENT_PATHS],
    )
    arguments = parser.parse_args(argv)
    exit_code = 0
    for path in arguments.paths:
        try:
            found = findings(path)
            label = rules_for(path).path.as_posix()
        except StudentGuardError as exc:
            print(f"student-guard: {exc}", file=sys.stderr)
            return 2
        if found:
            exit_code = 1
            print(f"student-guard: {label} will not be run until this is fixed:", file=sys.stderr)
            for finding in found:
                print(f"- {finding}", file=sys.stderr)
            continue
        print(f"student-guard: {label} uses only the supplied harness and asserts each outcome.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
