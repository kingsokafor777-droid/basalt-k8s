"""Helpers for extracting Pod specifications from standard Kubernetes workloads."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .parser import KubernetesManifest

__all__ = [
    "container_security_context",
    "containers",
    "is_windows_workload",
    "pod_security_context",
    "pod_spec",
]


def pod_spec(manifest: KubernetesManifest) -> dict[str, Any] | None:
    """Return the effective Pod specification nested within a supported workload."""

    spec = _mapping(manifest.body.get("spec"))
    if spec is None:
        return None
    if manifest.kind == "Pod":
        return spec
    if manifest.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
        template = _mapping(spec.get("template"))
        return _mapping(template.get("spec")) if template else None
    if manifest.kind == "CronJob":
        job_template = _mapping(spec.get("jobTemplate"))
        job_spec = _mapping(job_template.get("spec")) if job_template else None
        template = _mapping(job_spec.get("template")) if job_spec else None
        return _mapping(template.get("spec")) if template else None
    return None


def containers(spec: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield all regular, init, and ephemeral container declarations."""

    for field in ("containers", "initContainers", "ephemeralContainers"):
        value = spec.get(field)
        if not isinstance(value, list):
            continue
        for container in value:
            if isinstance(container, dict):
                yield container


def pod_security_context(spec: dict[str, Any]) -> dict[str, Any]:
    """Return a Pod-level security context or an empty mapping."""

    return _mapping(spec.get("securityContext")) or {}


def container_security_context(container: dict[str, Any]) -> dict[str, Any]:
    """Return a container-level security context or an empty mapping."""

    return _mapping(container.get("securityContext")) or {}


def is_windows_workload(spec: dict[str, Any]) -> bool:
    """Whether the Pod specification explicitly targets Windows."""

    os_config = _mapping(spec.get("os"))
    return bool(os_config and os_config.get("name") == "windows")


def _mapping(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None
