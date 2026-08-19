"""Safe Kubernetes manifest parsing with document-level source locations."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "KubernetesManifest",
    "KubernetesParseError",
    "KubernetesParser",
]


class KubernetesParseError(ValueError):
    """Raised when a Kubernetes YAML manifest cannot be safely parsed."""


@dataclass(frozen=True)
class KubernetesManifest:
    """One Kubernetes API object parsed from a YAML document."""

    api_version: str
    kind: str
    name: str
    namespace: str | None
    body: dict[str, Any]
    path: str
    start_line: int

    _CLUSTER_SCOPED = frozenset({"ClusterRole", "ClusterRoleBinding", "Namespace"})

    @property
    def identifier(self) -> str:
        """Return a stable source-addressable Kubernetes object identity."""

        if self.kind in self._CLUSTER_SCOPED:
            return f"{self.kind}/{self.name}"
        return f"{self.namespace or 'default'}/{self.kind}/{self.name}"


class KubernetesParser:
    """Parse local YAML manifests without contacting a Kubernetes API server."""

    _EXTENSIONS = frozenset({".yaml", ".yml"})
    _SKIPPED_DIRECTORIES = frozenset({".git", ".venv", "venv", "node_modules"})

    def discover(self, targets: list[str]) -> Iterator[Path]:
        """Yield sorted and unique Kubernetes YAML files beneath requested paths."""

        found: set[Path] = set()
        for raw_target in targets:
            target = Path(raw_target).expanduser()
            if target.is_file():
                if target.suffix.casefold() in self._EXTENSIONS:
                    found.add(target)
                continue
            if not target.is_dir():
                continue
            for candidate in target.rglob("*"):
                if candidate.suffix.casefold() not in self._EXTENSIONS:
                    continue
                if any(part in self._SKIPPED_DIRECTORIES for part in candidate.parts):
                    continue
                found.add(candidate)
        yield from sorted(found, key=lambda path: path.as_posix())

    def parse(self, path: Path) -> tuple[KubernetesManifest, ...]:
        """Parse every API object from one YAML file, including ``kind: List`` items."""

        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise KubernetesParseError(f"could not read {path}: {exc}") from exc
        try:
            values = list(yaml.safe_load_all(source))
            nodes = list(yaml.compose_all(source))
        except yaml.YAMLError as exc:
            raise KubernetesParseError(f"could not parse {path}: {exc}") from exc

        display_path = self._display_path(path)
        manifests: list[KubernetesManifest] = []
        for value, node in zip(values, nodes, strict=True):
            if not isinstance(value, dict) or node is None:
                continue
            start_line = node.start_mark.line + 1
            manifests.extend(self._from_document(value, display_path, start_line))
        return tuple(manifests)

    @classmethod
    def _from_document(
        cls, document: dict[str, Any], path: str, start_line: int
    ) -> list[KubernetesManifest]:
        if document.get("kind") == "List":
            items = document.get("items")
            if not isinstance(items, list):
                return []
            manifests: list[KubernetesManifest] = []
            for item in items:
                if isinstance(item, dict):
                    manifests.extend(cls._from_document(item, path, start_line))
            return manifests

        kind = document.get("kind")
        metadata = document.get("metadata")
        if not isinstance(kind, str) or not isinstance(metadata, dict):
            return []
        name = metadata.get("name")
        if not isinstance(name, str) or not name:
            return []
        api_version = document.get("apiVersion")
        namespace = metadata.get("namespace")
        return [
            KubernetesManifest(
                api_version=api_version if isinstance(api_version, str) else "",
                kind=kind,
                name=name,
                namespace=namespace if isinstance(namespace, str) else None,
                body=document,
                path=path,
                start_line=start_line,
            )
        ]

    @staticmethod
    def _display_path(path: Path) -> str:
        resolved = path.resolve()
        try:
            return resolved.relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            return resolved.as_posix()
