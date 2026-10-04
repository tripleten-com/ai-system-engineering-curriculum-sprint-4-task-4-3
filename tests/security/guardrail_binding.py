"""Coldline.

===================

File:              tests/security/guardrail_binding.py
Component:         Security tooling — Static guardrail-binding and reach check
Purpose:           Check, without importing them, that src/worker/use_cases.py calls the supplied
                    guardrail by the name it imports from worker.guardrail and rebinds neither
                    the name nor the module, and that neither it nor src/api/routes.py can reach
                    the test runner, the interpreter, or another module's bindings.
Interacts With:    src/worker/use_cases.py, src/api/routes.py, src/worker/guardrail.py,
                    tests/security/guardrail_observation.py, tests/security/guardrail_mutation.py,
                    tests/contract/test_negative_tests.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Trusted static analysis, verified bindings, mutation targets, a closed reach
                    for application code
Tools:             Python 3.12, ast

The ``validation-bypass`` mutation replaces every call spelled ``validate_summary(...)``
in the worker with one that accepts the raw answer. That proves something only when the
name it replaces is the supplied guardrail: a worker that defined its own
``validate_summary`` (one that recognises the three supplied answers, say), or rebound the
name or the ``worker.guardrail`` module to something else, would pass the live rows with
its own parser, fail the mutation rows for the wrong reason, and never run the schema.
This check reads the student's worker as bytes, parses it, and requires:

1. one ``from worker.guardrail import ...`` statement at module level that imports
   ``validate_summary`` under its own name (no ``as``), and no other import of the
   ``worker.guardrail`` module in any form (``import worker.guardrail``, ``import worker``,
   a relative import, ``from worker import guardrail``);
2. no other binding of the name ``validate_summary``: not a ``def``, a class, an
   assignment target (plain, annotated, augmented, walrus, ``for``, ``with``,
   ``except ... as``, a match capture, ``global`` or ``nonlocal``), a parameter, a
   lambda parameter, or a second import;
3. every other appearance of the name is the callee of a call (``validate_summary(...)``):
   handing the function to another name (``check = validate_summary``) would let a call
   through that name escape the mutation;
4. no attribute assignment on ``guardrail``, no ``sys.modules``, and none of the names
   that rebind a module or a global at runtime (``importlib``, ``sys``, ``builtins``).

The assessed checks import both student application files into the pytest process that
judges them (``tests/security/interaction.py`` builds the worker and the API from
``src/``), so code in either file could, at import time or on a call, reach the test
runner itself: replace ``_pytest.reports.TestReport.from_item_and_call`` so a failed
report is written as passed, reassign a marker, or rewrite another module's globals.
Review round 2 therefore applies three **reach rules** to both files, read as bytes:

5. no import, in any form, of ``pytest``, ``_pytest``, ``sys``, ``importlib``,
   ``builtins``, ``gc``, ``inspect``, ``ctypes``, ``types``, ``runpy``, or a submodule of
   one (``from _pytest.reports import TestReport``, ``import importlib.util``);
6. none of the names that run text as code or rebind a name at runtime: ``exec``,
   ``eval``, ``compile``, ``__import__``, ``globals``, ``setattr``, ``delattr`` and
   ``__builtins__``, whether called or handed on (``run = exec``), in any position;
7. no dunder attribute access: ``__dict__``, ``__globals__``, ``__code__``,
   ``__builtins__`` and ``__class__`` are the doors into a module's or a function's
   bindings, and no other ``x.__name__`` has a place in either file.

The rules are syntactic: they close the spelled doors, and the trusted observation in
``tests/security/guardrail_observation.py`` checks the worker's behaviour. A patch that
spells none of these and reaches the runner only through objects the harness hands in is
the recorded residual risk; the instructor reads the code, and the graded artifact is the
committed tree.

``python -m tests.security.guardrail_binding`` checks both files (or the files named on
the command line, by their names), prints the findings and exits 1 when there is one;
``tests/contract/test_negative_tests.py`` asserts the same as one assessed row, before it
runs the observation.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
WORKER_PATH = Path("src/worker/use_cases.py")
ROUTES_PATH = Path("src/api/routes.py")
# The two student application files, in the order they are checked.
APPLICATION_PATHS: tuple[Path, ...] = (WORKER_PATH, ROUTES_PATH)
GUARDRAIL_MODULE = "worker.guardrail"
GUARDRAIL_PACKAGE = "worker"
GUARDRAIL_NAME = "validate_summary"
# Modules whose import gives application code a path to the test runner, the interpreter's
# module table, or another module's bindings. The top-level name is matched, so every
# submodule (`_pytest.reports`, `importlib.util`, `ctypes.util`) is covered.
# The interpreter's module table, by the attribute name every module exposes it under.
MODULE_TABLE = "modules"
RUNNER_MODULES: frozenset[str] = frozenset(
    {
        "pytest",
        "_pytest",
        "sys",
        "importlib",
        "builtins",
        "gc",
        "inspect",
        "ctypes",
        "types",
        "runpy",
    }
)
# Names that run text as code or rebind a name at runtime; none has a place in either
# application file, as a call or handed on under another name.
DYNAMIC_NAMES: frozenset[str] = frozenset(
    {"exec", "eval", "compile", "__import__", "globals", "setattr", "delattr", "__builtins__"}
)
# The dunder attributes the reach rule names first; every other dunder attribute is
# refused the same way (`_is_dunder`).
INTERNAL_ATTRIBUTES: frozenset[str] = frozenset(
    {"__dict__", "__globals__", "__code__", "__builtins__", "__class__"}
)
# Worker-only: names that rebind a module or a global at runtime beyond the dynamic names
# (the module names are also refused as imports; `modules` is `sys.modules` by attribute).
REBINDING_NAMES: frozenset[str] = frozenset({"importlib", "sys", "builtins", "modules"})
IMPORT_HINT = (
    f"`from {GUARDRAIL_MODULE} import {GUARDRAIL_NAME}` (with any other names from that "
    "module) is the one way the worker may reach the supplied guardrail"
)
REACH_HINT = (
    "application code must not reach the test runner, the interpreter's module table, or "
    "another module's bindings"
)


class GuardrailBindingError(ValueError):
    """Report that an application file could not be read, as opposed to a finding about it."""


def _line(node: ast.AST) -> str:
    """Return ``line N`` for a node, for a finding."""
    return f"line {getattr(node, 'lineno', '?')}"


def _is_dunder(name: str) -> bool:
    """Return whether ``name`` is a dunder (``__dict__``)."""
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _parameters(arguments: ast.arguments) -> list[ast.arg]:
    """Return every parameter of a signature, ``*args`` and ``**kwargs`` included."""
    parameters = [*arguments.posonlyargs, *arguments.args]
    if arguments.vararg is not None:
        parameters.append(arguments.vararg)
    parameters.extend(arguments.kwonlyargs)
    if arguments.kwarg is not None:
        parameters.append(arguments.kwarg)
    return parameters


def _names_guardrail(node: ast.ImportFrom) -> bool:
    """Return whether a relative import reaches the guardrail module or its function."""
    last = (node.module or "").rsplit(".", 1)[-1]
    names = {alias.name for alias in node.names}
    return last == "guardrail" or "guardrail" in names or GUARDRAIL_NAME in names


def _import_findings(tree: ast.Module) -> list[str]:
    """Return every import that reaches the guardrail other than the one permitted form."""
    findings: list[str] = []
    imported: list[ast.ImportFrom] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                is_package = alias.name == GUARDRAIL_PACKAGE
                if is_package or alias.name.startswith(f"{GUARDRAIL_PACKAGE}."):
                    findings.append(
                        f"{_line(node)}: `import {alias.name}` is not permitted; {IMPORT_HINT}"
                    )
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            if node.level:
                if _names_guardrail(node):
                    findings.append(
                        f"{_line(node)}: a relative import of the guardrail is not permitted; "
                        f"{IMPORT_HINT}"
                    )
            elif module == GUARDRAIL_PACKAGE and any(
                alias.name == "guardrail" for alias in node.names
            ):
                findings.append(
                    f"{_line(node)}: `from {GUARDRAIL_PACKAGE} import guardrail` is not "
                    f"permitted; {IMPORT_HINT}"
                )
            elif module == GUARDRAIL_MODULE:
                imported.append(node)
            else:
                for alias in node.names:
                    if GUARDRAIL_NAME in (alias.name, alias.asname):
                        findings.append(
                            f"{_line(node)}: `{GUARDRAIL_NAME}` imported from `{module}` is not "
                            f"the supplied guardrail; {IMPORT_HINT}"
                        )
    top_level = [node for node in tree.body if isinstance(node, ast.ImportFrom)]
    bound = [
        node
        for node in imported
        if any(alias.name == GUARDRAIL_NAME and alias.asname is None for alias in node.names)
    ]
    if not bound:
        findings.append(
            f"the worker does not import `{GUARDRAIL_NAME}` from `{GUARDRAIL_MODULE}`; "
            f"{IMPORT_HINT}"
        )
    elif len(bound) > 1:
        findings.append(
            f"`{GUARDRAIL_NAME}` is imported {len(bound)} times; import it once, at module level"
        )
    for node in imported:
        if node not in top_level:
            findings.append(
                f"{_line(node)}: the guardrail import must be at module level, not inside a "
                "function or a block"
            )
        for alias in node.names:
            if alias.name == "*":
                findings.append(
                    f"{_line(node)}: `from {GUARDRAIL_MODULE} import *` is not permitted"
                )
            elif alias.asname is not None and GUARDRAIL_NAME in (alias.name, alias.asname):
                findings.append(
                    f"{_line(node)}: `{alias.name} as {alias.asname}` rebinds the guardrail; "
                    f"import `{GUARDRAIL_NAME}` under its own name"
                )
    return findings


def _binding_findings(tree: ast.Module) -> list[str]:
    """Return every binding of the guardrail's name other than its import, and every escape."""
    findings: list[str] = []
    callees: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == GUARDRAIL_NAME:
                callees.add(id(node.func))

    def rebinds(node: ast.AST, how: str) -> None:
        findings.append(
            f"{_line(node)}: {how} rebinds `{GUARDRAIL_NAME}`; the name must stay the supplied "
            "guardrail's import"
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == GUARDRAIL_NAME:
            if isinstance(node.ctx, ast.Store | ast.Del):
                rebinds(node, "an assignment to the name")
            elif id(node) not in callees:
                findings.append(
                    f"{_line(node)}: `{GUARDRAIL_NAME}` is used other than as the callee of a "
                    "call; hand the raw answer to `validate_summary(...)` directly"
                )
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and (
                node.name == GUARDRAIL_NAME
            ):
                rebinds(node, "a function definition")
            for parameter in _parameters(node.args):
                if parameter.arg == GUARDRAIL_NAME:
                    rebinds(parameter, "a parameter")
        elif isinstance(node, ast.ClassDef) and node.name == GUARDRAIL_NAME:
            rebinds(node, "a class definition")
        elif isinstance(node, ast.ExceptHandler) and node.name == GUARDRAIL_NAME:
            rebinds(node, "an exception handler")
        elif isinstance(node, ast.Global | ast.Nonlocal) and GUARDRAIL_NAME in node.names:
            rebinds(node, "a global or nonlocal statement")
        elif isinstance(node, ast.MatchAs | ast.MatchStar) and node.name == GUARDRAIL_NAME:
            rebinds(node, "a match capture")
        elif isinstance(node, ast.Attribute):
            if node.attr == GUARDRAIL_NAME and isinstance(node.ctx, ast.Store | ast.Del):
                rebinds(node, "an attribute assignment")
            if node.attr in REBINDING_NAMES or (
                isinstance(node.value, ast.Name) and node.value.id in REBINDING_NAMES
            ):
                findings.append(
                    f"{_line(node)}: `{ast.unparse(node)}` is not permitted in the worker; it "
                    "can rebind a module or a global at runtime"
                )
        if isinstance(node, ast.Name) and node.id in REBINDING_NAMES and node.id != "modules":
            findings.append(
                f"{_line(node)}: `{node.id}` is not permitted in the worker; it can rebind a "
                "module or a global at runtime"
            )
    return findings


def _top_module(dotted: str) -> str:
    """Return the first component of a dotted module path."""
    return dotted.split(".", 1)[0]


def reach_findings(tree: ast.Module) -> list[str]:
    """Return every spelled path from application code to the runner or another module's bindings.

    Rules 5 to 7 of the module docstring, over any application file: an import of a
    runner module or a submodule of one, a dynamic name in any position, and a dunder
    attribute access.
    """
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _top_module(alias.name) in RUNNER_MODULES:
                    findings.append(
                        f"{_line(node)}: `import {alias.name}` is not permitted in application "
                        f"code; the module can reach the test runner or rebind a module or a "
                        f"global at runtime; {REACH_HINT}"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and _top_module(node.module or "") in RUNNER_MODULES:
                names = ", ".join(alias.name for alias in node.names)
                findings.append(
                    f"{_line(node)}: `from {node.module} import {names}` is not permitted in "
                    f"application code; the module can reach the test runner or rebind a module "
                    f"or a global at runtime; {REACH_HINT}"
                )
            else:
                for alias in node.names:
                    if alias.name in RUNNER_MODULES or alias.name == MODULE_TABLE:
                        findings.append(
                            f"{_line(node)}: importing `{alias.name}` from `{node.module}` is "
                            f"not permitted in application code; a runner module reached "
                            f"through another module is the same door; {REACH_HINT}"
                        )
        elif isinstance(node, ast.Name) and node.id in DYNAMIC_NAMES:
            findings.append(
                f"{_line(node)}: `{node.id}` is not permitted in application code; it runs text "
                f"as code or can rebind a module or a global at runtime; {REACH_HINT}"
            )
        elif isinstance(node, ast.Attribute) and (
            node.attr in RUNNER_MODULES or node.attr == MODULE_TABLE
        ):
            findings.append(
                f"{_line(node)}: `{ast.unparse(node)}` is not permitted in application code; a "
                f"runner module or the module table reached as another module's attribute is "
                f"the same door as importing it; {REACH_HINT}"
            )
        elif isinstance(node, ast.Attribute) and (
            node.attr in INTERNAL_ATTRIBUTES or _is_dunder(node.attr)
        ):
            findings.append(
                f"{_line(node)}: `{ast.unparse(node)}` is not permitted in application code; a "
                f"dunder attribute reaches a module's, a class's or a function's bindings; "
                f"{REACH_HINT}"
            )
    return findings


def rules_for(path: Path) -> str:
    """Return which rules a file gets, by its name: ``worker`` or ``route``; or raise."""
    if path.name == WORKER_PATH.name:
        return "worker"
    if path.name == ROUTES_PATH.name:
        return "route"
    names = ", ".join(item.as_posix() for item in APPLICATION_PATHS)
    raise GuardrailBindingError(f"{path.name} is not an application file of this Task ({names})")


def findings_for_source(source: str | bytes, path: Path = WORKER_PATH) -> list[str]:
    """Return every reason the file at ``path`` fails its rules.

    The worker gets the binding rules (1 to 4) and the reach rules (5 to 7); the route
    module gets the reach rules. Findings are deduplicated and keep their first position.
    """
    rules = rules_for(path)
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{path.as_posix()} is not valid Python: {exc}"]
    except ValueError as exc:
        return [f"{path.as_posix()} could not be decoded as UTF-8: {exc}"]
    found = [*_import_findings(tree), *_binding_findings(tree)] if rules == "worker" else []
    found.extend(reach_findings(tree))
    seen: set[str] = set()
    ordered: list[str] = []
    for finding in found:
        if finding not in seen:
            seen.add(finding)
            ordered.append(finding)
    return ordered


def findings(path: Path) -> list[str]:
    """Return the findings for the application file at ``path``, read as bytes."""
    try:
        source = path.read_bytes()
    except OSError as exc:
        raise GuardrailBindingError(f"{path.as_posix()} could not be read: {exc}") from exc
    return findings_for_source(source, path)


def application_findings(root: Path = TASK_ROOT) -> list[str]:
    """Return the findings of both application files under ``root``, each prefixed by its path."""
    found: list[str] = []
    for relative in APPLICATION_PATHS:
        found.extend(f"{relative.as_posix()}: {item}" for item in findings(root / relative))
    return found


def main(argv: list[str] | None = None) -> int:
    """Check both application files (or those named) and print the findings."""
    parser = argparse.ArgumentParser(
        description=(
            "Check that the worker calls the supplied guardrail by its imported name and that "
            "neither application file reaches the test runner."
        )
    )
    parser.add_argument(
        "paths", nargs="*", type=Path, default=[TASK_ROOT / path for path in APPLICATION_PATHS]
    )
    arguments = parser.parse_args(argv)
    exit_code = 0
    for path in arguments.paths:
        try:
            rules = rules_for(path)
            found = findings(path)
        except GuardrailBindingError as exc:
            print(f"guardrail-binding: {exc}", file=sys.stderr)
            return 2
        label = (WORKER_PATH if rules == "worker" else ROUTES_PATH).as_posix()
        if found:
            exit_code = 1
            what = (
                "does not call the supplied guardrail by its imported name, or reaches beyond "
                "application code"
                if rules == "worker"
                else "reaches beyond application code"
            )
            print(f"guardrail-binding: {label} {what}:", file=sys.stderr)
            for finding in found:
                print(f"- {finding}", file=sys.stderr)
            continue
        if rules == "worker":
            print(
                f"guardrail-binding: {label} imports `{GUARDRAIL_NAME}` from "
                f"`{GUARDRAIL_MODULE}`, rebinds nothing, and reaches nothing beyond application "
                "code."
            )
        else:
            print(f"guardrail-binding: {label} reaches nothing beyond application code.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
