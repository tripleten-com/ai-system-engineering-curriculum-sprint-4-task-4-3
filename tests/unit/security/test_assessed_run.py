"""Coldline.

===================

File:              tests/unit/security/test_assessed_run.py
Component:         Unit tests — Assessed-module runner
Purpose:           Prove the runner's inventory agrees with the assessed modules' source, that a
                    skipped, missing, failed or unregistered case fails the step, and that a real
                    run is compared outside the pytest process.
Interacts With:    tests/security/assessed_run.py, tests/contract/test_output_audit.py,
                    tests/contract/test_negative_tests.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Closed inventories, skipped is not passed
Tools:             Python 3.12, pytest, junit XML

The assessed modules are parsed here, never imported: they import the student's route
through the harness, which is the very thing the runner keeps out of its own process.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from tests.security import assessed_run

TASK_ROOT = Path(__file__).resolve().parents[3]
_PARAMETER = re.compile(r"\[.*\]$")


def _report(path: Path, rows: list[tuple[str, str]]) -> Path:
    """Write a junit report with one testcase per (name, outcome element or "")."""
    cases = "".join(
        f"<testcase classname='tests.contract.test_x' name='{name}' time='0.1'>"
        + (f"<{outcome} message='x' />" if outcome else "")
        + "</testcase>"
        for name, outcome in rows
    )
    path.write_text(
        "<?xml version='1.0'?><testsuites><testsuite name='pytest'>"
        + cases
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def test_every_registered_module_exists_and_its_test_functions_match_the_inventory() -> None:
    """The function names in each module's source are exactly the inventory's, parameters aside."""
    for module, cases in assessed_run.REGISTERED_CASES.items():
        path = TASK_ROOT / module
        assert path.is_file(), module
        tree = ast.parse(path.read_text(encoding="utf-8"))
        defined = {
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name.startswith("test_")
        }
        registered = {_PARAMETER.sub("", name) for name in cases}
        assert registered == defined, module
        assert len(cases) == len(set(cases)), module


def test_the_eligibility_cases_cover_every_state_twice_plus_missing_and_refused() -> None:
    """One case per state with and without a summary, then the 404 and the refusal."""
    names = [case.split("[", 1)[1].rstrip("]") for case in assessed_run.ELIGIBILITY_CASES]
    assert names[-2:] == ["missing", "refused"]
    labels = {
        "no-summary" if name.endswith("-no-summary") else name.rsplit("-", 1)[1]
        for name in names[:-2]
    }
    assert labels == {"stored", "no-summary"}
    states = [name.removesuffix("-no-summary").removesuffix("-stored") for name in names[:-2]]
    assert states[::2] == states[1::2]
    assert "COMPLETED" in states and "NEEDS_REVIEW" in states and "QUEUED" in states
    assert len(names) == 2 * len(set(states)) + 2


def test_compare_names_missing_skipped_failed_errored_and_unregistered_cases() -> None:
    """Every registered case must be present and passed; anything else is named."""
    module = "tests/contract/test_negative_tests.py"
    registered = list(assessed_run.REGISTERED_CASES[module])
    outcomes = dict.fromkeys(registered, "passed")
    assert assessed_run.compare(module, outcomes) == []

    outcomes[registered[0]] = "skipped"
    outcomes[registered[1]] = "failed"
    outcomes[registered[2]] = "error"
    del outcomes[registered[3]]
    outcomes["test_added_by_someone"] = "passed"
    found = assessed_run.compare(module, outcomes)
    assert f"{registered[0]} skipped" in found
    assert f"{registered[1]} failed" in found
    assert f"{registered[2]} error" in found
    assert f"{registered[3]} did not run (missing from the report)" in found
    unregistered = "test_added_by_someone is not a registered case"
    assert any(finding.startswith(unregistered) for finding in found)
    assert len(found) == 5

    with pytest.raises(assessed_run.AssessedRunError, match="not a registered assessed module"):
        assessed_run.compare("tests/contract/test_other.py", {})


def test_outcomes_are_read_from_the_report_and_a_duplicate_name_is_an_error(tmp_path: Path) -> None:
    """Passed, failed, error and skipped are told apart; a repeated name is a tooling error."""
    report = _report(
        tmp_path / "r.xml",
        [("test_a", ""), ("test_b", "failure"), ("test_c", "error"), ("test_d[x]", "skipped")],
    )
    assert assessed_run.outcomes_of(report) == {
        "test_a": "passed",
        "test_b": "failed",
        "test_c": "error",
        "test_d[x]": "skipped",
    }
    with pytest.raises(assessed_run.AssessedRunError, match="twice"):
        assessed_run.outcomes_of(_report(tmp_path / "d.xml", [("test_a", ""), ("test_a", "")]))
    with pytest.raises(assessed_run.AssessedRunError, match="no junit report"):
        assessed_run.outcomes_of(tmp_path / "absent.xml")


def test_deselecting_options_are_refused() -> None:
    """`-k`, `-m` and `--deselect` would hide a case; the runner refuses them before running."""
    for option in ("-k", "-m", "--deselect", "-k=x", "--deselect=tests/x.py::test_a"):
        assert assessed_run.refused_option(option), option
        with pytest.raises(assessed_run.AssessedRunError, match="every assessed case must run"):
            assessed_run.run("tests/contract/test_negative_tests.py", [option, "x"])
    assert not assessed_run.refused_option("-q")
    assert not assessed_run.refused_option("--maxfail=1")


def test_a_real_run_is_compared_outside_the_pytest_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A module whose second case is skipped exits 0 under pytest and still fails the step."""
    module = "tests/contract/test_probe.py"
    (tmp_path / "tests/contract").mkdir(parents=True)
    (tmp_path / module).write_text(
        "import pytest\n\n\ndef test_a():\n    assert True\n\n\n"
        "@pytest.mark.skip(reason='probe')\ndef test_b():\n    assert True\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(assessed_run.REGISTERED_CASES, module, ("test_a", "test_b"))

    returncode, findings = assessed_run.run(module, ["-q", "-p", "no:cacheprovider"], root=tmp_path)

    assert returncode == 0
    assert findings == ["test_b skipped"]

    (tmp_path / module).write_text(
        "def test_a():\n    assert True\n\n\ndef test_b():\n    assert True\n", encoding="utf-8"
    )
    returncode, findings = assessed_run.run(module, ["-q", "-p", "no:cacheprovider"], root=tmp_path)
    assert (returncode, findings) == (0, [])


def test_main_reports_the_verdict_and_keeps_pytests_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 0 when all passed; 1 when a case did not pass, whatever pytest's exit; 2 on an error."""
    module = "tests/contract/test_negative_tests.py"
    monkeypatch.setattr(assessed_run, "run", lambda *args, **kwargs: (0, []))
    assert assessed_run.main([module]) == 0
    assert "all 6 registered cases executed and passed" in capsys.readouterr().out

    monkeypatch.setattr(assessed_run, "run", lambda *args, **kwargs: (0, ["test_x skipped"]))
    assert assessed_run.main([module]) == 1
    assert "- test_x skipped" in capsys.readouterr().err

    monkeypatch.setattr(assessed_run, "run", lambda *args, **kwargs: (1, ["test_x failed"]))
    assert assessed_run.main([module]) == 1

    def refuse(*args: object, **kwargs: object) -> tuple[int, list[str]]:
        raise assessed_run.AssessedRunError("refused")

    monkeypatch.setattr(assessed_run, "run", refuse)
    assert assessed_run.main([module]) == 2
    assert "assessed-run: refused" in capsys.readouterr().err
    assert assessed_run.main([]) == 2
    assert assessed_run.main(["-q"]) == 2
