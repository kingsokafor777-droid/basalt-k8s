"""Tests for the Kubernetes posture scanner command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from basalt_k8s.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_checks_lists_every_registered_rule(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["checks", "--verbose"]) == 0
    output = capsys.readouterr().out

    assert "rbac.wildcard-permissions" in output
    assert "network.namespace-default-deny-missing" in output
    assert "8 checks across 3 posture areas" in output


def test_scan_defaults_to_sarif_and_writes_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "results.sarif"

    assert main(["scan", str(FIXTURES / "insecure.yaml"), "--output", str(output)]) == 0
    captured = capsys.readouterr()
    sarif = json.loads(output.read_text(encoding="utf-8"))

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 8
    assert "wrote" in captured.err


def test_fail_on_returns_nonzero_for_violations(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(FIXTURES / "insecure.yaml"), "--fail-on", "critical"]) == 1
    assert '"version": "2.1.0"' in capsys.readouterr().out


def test_unknown_rule_returns_configuration_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(FIXTURES), "--rule", "not-a-rule"]) == 2
    assert "unknown rule ids" in capsys.readouterr().err


def test_parser_rejects_missing_command() -> None:
    with pytest.raises(SystemExit):
        main([])
