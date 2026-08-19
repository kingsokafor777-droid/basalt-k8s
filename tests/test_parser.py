"""Tests for Kubernetes YAML parsing and manifest source locations."""

from __future__ import annotations

from pathlib import Path

import pytest

from basalt_k8s.parser import KubernetesParseError, KubernetesParser

FIXTURES = Path(__file__).parent / "fixtures"


def test_parser_extracts_multidocument_kubernetes_objects() -> None:
    manifests = KubernetesParser().parse(FIXTURES / "insecure.yaml")

    assert [manifest.identifier for manifest in manifests] == [
        "Namespace/production",
        "production/Role/wildcard-reader",
        "ClusterRoleBinding/application-superuser",
        "production/ServiceAccount/default",
        "production/Deployment/insecure-api",
    ]
    assert manifests[0].start_line == 1
    assert manifests[-1].start_line > manifests[0].start_line
    assert manifests[-1].path.endswith("tests/fixtures/insecure.yaml")


def test_discover_recurses_but_skips_virtual_environments(tmp_path: Path) -> None:
    root_file = tmp_path / "root.yaml"
    root_file.write_text(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: root\n",
        encoding="utf-8",
    )
    nested_dir = tmp_path / "apps"
    nested_dir.mkdir()
    nested_file = nested_dir / "app.yml"
    nested_file.write_text(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: app\n",
        encoding="utf-8",
    )
    ignored_dir = tmp_path / ".venv" / "charts"
    ignored_dir.mkdir(parents=True)
    ignored_file = ignored_dir / "ignored.yaml"
    ignored_file.write_text(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: ignored\n",
        encoding="utf-8",
    )

    discovered = list(KubernetesParser().discover([str(tmp_path)]))

    assert discovered == [nested_file, root_file]


def test_parser_reports_invalid_yaml_with_file_context(tmp_path: Path) -> None:
    source = tmp_path / "broken.yaml"
    source.write_text("apiVersion: v1\nkind: Namespace\nmetadata: [\n", encoding="utf-8")

    with pytest.raises(KubernetesParseError, match=r"broken\.yaml"):
        KubernetesParser().parse(source)
