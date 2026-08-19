"""Declarative registry for Kubernetes posture checks."""

from __future__ import annotations

import abc
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

from basalt_core import (
    Evidence,
    Exploitability,
    Exposure,
    Finding,
    Location,
    Provider,
    Remediation,
    ResourceRef,
    Severity,
)

from .parser import KubernetesManifest

if TYPE_CHECKING:  # pragma: no cover
    from .scanner import KubernetesContext

__all__ = ["CHECKS", "Check", "checks_for_kind", "get_check", "register"]


class Check(abc.ABC):
    """One declarative Kubernetes posture rule."""

    rule_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    exposure: Exposure = Exposure.INTERNAL
    exploitability: Exploitability = Exploitability.MODERATE
    control_ids: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    tags: tuple[str, ...] = ("kubernetes",)

    @abc.abstractmethod
    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        """Yield findings for one matching Kubernetes manifest."""

    def finding(
        self,
        manifest: KubernetesManifest,
        *,
        evidence: list[Evidence] | None = None,
        remediation: Remediation | None = None,
        title: str | None = None,
        description: str | None = None,
        severity: Severity | None = None,
        exposure: Exposure | None = None,
    ) -> Finding:
        """Build a normalized finding anchored at a Kubernetes YAML document."""

        return Finding(
            rule_id=self.rule_id,
            title=title or self.title,
            description=description or self.description,
            severity=severity or self.severity,
            exposure=exposure or self.exposure,
            exploitability=self.exploitability,
            resource=ResourceRef(
                provider=Provider.KUBERNETES,
                resource_type=manifest.kind,
                uid=manifest.identifier,
                name=manifest.name,
                region=manifest.namespace,
                tags={"manifest_path": manifest.path},
            ),
            scanner="basalt-k8s",
            control_ids=list(self.control_ids),
            evidence=evidence or [],
            remediation=remediation,
            location=Location(path=manifest.path, start_line=manifest.start_line),
            tags=list(self.tags),
        )


CHECKS: list[type[Check]] = []


def register(cls: type[Check]) -> type[Check]:
    """Register a check and reject incomplete or duplicate definitions at import time."""

    if not cls.rule_id:
        raise ValueError(f"{cls.__name__} must declare a rule_id")
    if not cls.kinds:
        raise ValueError(f"{cls.__name__} must declare kinds")
    if cls.rule_id in {candidate.rule_id for candidate in CHECKS}:
        raise ValueError(f"duplicate rule_id {cls.rule_id!r}")
    CHECKS.append(cls)
    return cls


def get_check(rule_id: str) -> type[Check]:
    """Return a registered check by stable rule identifier."""

    for cls in CHECKS:
        if cls.rule_id == rule_id:
            return cls
    raise KeyError(f"no check with rule_id {rule_id!r}")


def checks_for_kind(kind: str) -> Iterator[type[Check]]:
    """Yield checks that apply to the Kubernetes resource kind."""

    for cls in CHECKS:
        if kind in cls.kinds:
            yield cls
