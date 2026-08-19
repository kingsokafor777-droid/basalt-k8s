"""Rule behavior and Basalt plugin-contract tests."""

from __future__ import annotations

from pathlib import Path

from basalt_core import ScanContext, discover_scanners, load_catalog

from basalt_k8s.registry import CHECKS
from basalt_k8s.scanner import KubernetesScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_every_declared_control_resolves_in_basalt_core() -> None:
    catalog = load_catalog()
    unresolved = {
        control_id for check in CHECKS for control_id in catalog.unknown(check.control_ids)
    }

    assert unresolved == set()


def test_plugin_is_discovered_through_core_entry_point() -> None:
    scanners = discover_scanners()

    assert scanners["k8s"] is KubernetesScanner


def test_insecure_fixture_emits_each_initial_rule() -> None:
    result = KubernetesScanner().run(ScanContext(paths=[str(FIXTURES / "insecure.yaml")]))

    assert result.metadata.provider.value == "kubernetes"
    assert result.metadata.errors == []
    assert {finding.rule_id for finding in result.findings} == {
        "rbac.wildcard-permissions",
        "rbac.cluster-admin-binding",
        "rbac.default-service-account-automount",
        "pod.privileged-container",
        "pod.host-namespaces-enabled",
        "pod.run-as-non-root-missing",
        "pod.read-only-root-filesystem-missing",
        "network.namespace-default-deny-missing",
    }
    assert all(finding.location is not None for finding in result.findings)
    assert all(
        finding.location.path.endswith("tests/fixtures/insecure.yaml")
        for finding in result.findings
    )


def test_secure_fixture_emits_no_findings() -> None:
    result = KubernetesScanner().run(ScanContext(paths=[str(FIXTURES / "secure.yaml")]))

    assert result.findings == []
    assert result.metadata.errors == []


def test_rule_filter_runs_only_requested_rule() -> None:
    result = KubernetesScanner().run(
        ScanContext(
            paths=[str(FIXTURES / "insecure.yaml")],
            rule_filter=["pod.privileged-container"],
        )
    )

    assert [finding.rule_id for finding in result.findings] == ["pod.privileged-container"]


def test_unparseable_file_is_recorded_without_discarding_healthy_results(tmp_path: Path) -> None:
    malformed = tmp_path / "broken.yaml"
    malformed.write_text("apiVersion: v1\nkind: Namespace\nmetadata: [\n", encoding="utf-8")
    healthy = tmp_path / "healthy.yaml"
    healthy.write_text(
        "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: default\n",
        encoding="utf-8",
    )

    result = KubernetesScanner().run(ScanContext(paths=[str(tmp_path)]))

    assert [finding.rule_id for finding in result.findings] == [
        "rbac.default-service-account-automount"
    ]
    assert len(result.metadata.errors) == 1
    assert "broken.yaml" in result.metadata.errors[0]


def test_unknown_rule_filter_is_rejected_by_cli_contract() -> None:
    from basalt_k8s.cli import main

    assert main(["scan", str(FIXTURES), "--rule", "not-a-rule"]) == 2
