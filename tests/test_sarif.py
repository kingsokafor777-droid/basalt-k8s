"""Tests for Kubernetes findings emitted through the shared SARIF exporter."""

from __future__ import annotations

import json
from pathlib import Path

from basalt_core import ScanContext, get_emitter

from basalt_k8s.scanner import KubernetesScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_kubernetes_findings_emit_github_code_scanning_sarif() -> None:
    result = KubernetesScanner().run(ScanContext(paths=[str(FIXTURES / "insecure.yaml")]))
    sarif = json.loads(get_emitter("sarif").emit_json(result))

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "basalt-k8s"
    assert len(run["results"]) == 8
    privileged = next(
        item for item in run["results"] if item["ruleId"] == "pod.privileged-container"
    )
    location = privileged["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"].endswith("tests/fixtures/insecure.yaml")
    assert location["region"]["startLine"] > 1
    assert privileged["partialFingerprints"]["basaltFingerprint/v1"]
    rule = next(
        item for item in run["tool"]["driver"]["rules"] if item["id"] == "pod.privileged-container"
    )
    assert "cis-k8s:pod.no-privileged" in rule["properties"]["controls"]
