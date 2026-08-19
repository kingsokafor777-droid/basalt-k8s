"""Kubernetes posture scanner entry point discovered by Basalt Core."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from basalt_core import Finding, Provider, ScanContext, Scanner

from . import checks as _checks  # noqa: F401 - importing registers every check
from .parser import KubernetesManifest, KubernetesParseError, KubernetesParser
from .registry import CHECKS, Check, checks_for_kind

__all__ = ["KubernetesContext", "KubernetesScanner", "__version__"]

__version__ = "0.1.0"


@dataclass(frozen=True)
class KubernetesContext:
    """Cross-manifest static-analysis context that requires no Kubernetes credentials."""

    paths: tuple[str, ...]
    manifests: tuple[KubernetesManifest, ...]

    @classmethod
    def build(
        cls,
        scan_context: ScanContext,
        manifests: tuple[KubernetesManifest, ...],
    ) -> KubernetesContext:
        """Create scanner context from local source paths and parsed Kubernetes objects."""

        paths = tuple(scan_context.paths) or (str(Path.cwd()),)
        return cls(paths=paths, manifests=manifests)

    def has_default_deny_network_policy(self, namespace: str) -> bool:
        """Whether scanned manifests define a default deny-all policy for one namespace."""

        return any(
            self._is_default_deny_policy(manifest, namespace)
            for manifest in self.manifests
            if manifest.kind == "NetworkPolicy"
        )

    @staticmethod
    def _is_default_deny_policy(manifest: KubernetesManifest, namespace: str) -> bool:
        if (manifest.namespace or "default") != namespace:
            return False
        spec = manifest.body.get("spec")
        if not isinstance(spec, dict) or spec.get("podSelector") != {}:
            return False
        policy_types = spec.get("policyTypes")
        if not isinstance(policy_types, list) or not {"Ingress", "Egress"} <= set(policy_types):
            return False
        ingress = spec.get("ingress", [])
        egress = spec.get("egress", [])
        return isinstance(ingress, list) and not ingress and isinstance(egress, list) and not egress


class KubernetesScanner(Scanner):
    """Static Kubernetes manifest scanner that never contacts a cluster or executes kubectl."""

    name = "basalt-k8s"
    version = __version__
    provider = Provider.KUBERNETES
    description = "Kubernetes RBAC, Pod Security, and NetworkPolicy checks with SARIF output"

    def __init__(
        self,
        checks: list[type[Check]] | None = None,
        parser: KubernetesParser | None = None,
    ) -> None:
        self._checks = list(checks if checks is not None else CHECKS)
        self._parser = parser or KubernetesParser()

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        """Parse Kubernetes YAML and yield posture findings without cluster interaction."""

        paths = tuple(context.paths) or (str(Path.cwd()),)
        errors: list[str] = []
        manifests: list[KubernetesManifest] = []
        for path in self._parser.discover(list(paths)):
            try:
                manifests.extend(self._parser.parse(path))
            except KubernetesParseError as exc:
                errors.append(str(exc))
        k8s_context = KubernetesContext.build(context, tuple(manifests))
        for manifest in manifests:
            for cls in checks_for_kind(manifest.kind):
                if cls not in self._checks or not context.selects(cls.rule_id):
                    continue
                check = cls()
                try:
                    yield from check.run(manifest, k8s_context)
                except Exception as exc:
                    errors.append(
                        f"{manifest.path}:{manifest.start_line} {cls.rule_id}: "
                        f"{type(exc).__name__}: {exc}"
                    )
        if errors:
            raise RuntimeError("; ".join(errors))

    @property
    def check_count(self) -> int:
        """Return the number of checks configured on this scanner instance."""

        return len(self._checks)
