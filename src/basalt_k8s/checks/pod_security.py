"""Kubernetes Pod Security Standards posture checks."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from basalt_core import Evidence, Exposure, Finding, Remediation, Severity

from ..parser import KubernetesManifest
from ..registry import Check, register
from ..workloads import (
    container_security_context,
    containers,
    is_windows_workload,
    pod_security_context,
    pod_spec,
)

if TYPE_CHECKING:  # pragma: no cover
    from ..scanner import KubernetesContext


WORKLOAD_KINDS = ("Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob")
_PSS_REFERENCE = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"


class PodSecurityCheck(Check):
    """Shared metadata and workload extraction for Pod Security checks."""

    kinds = WORKLOAD_KINDS
    tags: tuple[str, ...] = ("kubernetes", "pod-security")

    @staticmethod
    def _spec(manifest: KubernetesManifest) -> dict[str, Any] | None:
        return pod_spec(manifest)


@register
class PrivilegedContainer(PodSecurityCheck):
    """Find workloads with explicitly privileged containers."""

    rule_id = "pod.privileged-container"
    title = "Workload runs a privileged container"
    description = "A regular, init, or ephemeral container explicitly sets privileged to true."
    severity = Severity.CRITICAL
    exposure = Exposure.INTERNAL
    control_ids = ("cis-k8s:pod.no-privileged",)
    tags = ("kubernetes", "pod-security", "privileged")

    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        spec = self._spec(manifest)
        if spec is None:
            return
        affected = [
            container.get("name", "<unnamed>")
            for container in containers(spec)
            if container_security_context(container).get("privileged") is True
        ]
        if not affected:
            return
        yield self.finding(
            manifest,
            evidence=[
                Evidence(
                    description="privileged containers",
                    observed=affected,
                    expected="no container with securityContext.privileged: true",
                    source="spec.*Containers[].securityContext.privileged",
                )
            ],
            remediation=Remediation(
                summary="Remove privileged mode and grant only the required capabilities.",
                iac_patch="securityContext:\n  privileged: false",
                references=[_PSS_REFERENCE],
            ),
        )


@register
class HostNamespacesEnabled(PodSecurityCheck):
    """Find workloads that share host network, PID, or IPC namespaces."""

    rule_id = "pod.host-namespaces-enabled"
    title = "Workload shares a host namespace"
    description = "The Pod specification enables hostNetwork, hostPID, or hostIPC."
    severity = Severity.HIGH
    exposure = Exposure.INTERNAL
    control_ids = ("cis-k8s:pod.no-host-namespaces",)
    tags = ("kubernetes", "pod-security", "host-namespace")

    _FIELDS = ("hostNetwork", "hostPID", "hostIPC")

    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        spec = self._spec(manifest)
        if spec is None:
            return
        enabled = [field for field in self._FIELDS if spec.get(field) is True]
        if not enabled:
            return
        yield self.finding(
            manifest,
            evidence=[
                Evidence(
                    description="enabled host namespace fields",
                    observed=enabled,
                    expected="hostNetwork, hostPID, and hostIPC disabled",
                    source="PodSpec",
                )
            ],
            remediation=Remediation(
                summary=(
                    "Disable host namespace sharing unless a reviewed infrastructure "
                    "workload requires it."
                ),
                iac_patch="hostNetwork: false\nhostPID: false\nhostIPC: false",
                references=[_PSS_REFERENCE],
            ),
        )


@register
class ContainersRunAsNonRoot(PodSecurityCheck):
    """Find Linux workloads that do not require non-root container execution."""

    rule_id = "pod.run-as-non-root-missing"
    title = "Workload does not require non-root execution"
    description = "One or more containers lack an effective securityContext.runAsNonRoot: true."
    severity = Severity.HIGH
    exposure = Exposure.INTERNAL
    control_ids = ("cis-k8s:pod.run-as-non-root",)
    tags = ("kubernetes", "pod-security", "non-root")

    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        spec = self._spec(manifest)
        if spec is None or is_windows_workload(spec):
            return
        pod_context = pod_security_context(spec)
        affected: list[str] = []
        for container in containers(spec):
            context_value = container_security_context(container).get(
                "runAsNonRoot", pod_context.get("runAsNonRoot")
            )
            if context_value is not True:
                affected.append(str(container.get("name", "<unnamed>")))
        if not affected:
            return
        yield self.finding(
            manifest,
            evidence=[
                Evidence(
                    description="containers without effective runAsNonRoot",
                    observed=affected,
                    expected=True,
                    source="PodSpec.securityContext or container securityContext",
                )
            ],
            remediation=Remediation(
                summary="Require every Linux container to run as a non-root user.",
                iac_patch="securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
                references=[_PSS_REFERENCE],
            ),
        )


@register
class ReadOnlyRootFilesystem(PodSecurityCheck):
    """Find containers that do not explicitly use a read-only root filesystem."""

    rule_id = "pod.read-only-root-filesystem-missing"
    title = "Workload does not use a read-only root filesystem"
    description = "One or more containers lack securityContext.readOnlyRootFilesystem: true."
    severity = Severity.MEDIUM
    exposure = Exposure.INTERNAL
    control_ids = ("cis-k8s:pod.read-only-root-fs",)
    tags = ("kubernetes", "pod-security", "filesystem")

    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        spec = self._spec(manifest)
        if spec is None or is_windows_workload(spec):
            return
        affected = [
            str(container.get("name", "<unnamed>"))
            for container in containers(spec)
            if container_security_context(container).get("readOnlyRootFilesystem") is not True
        ]
        if not affected:
            return
        yield self.finding(
            manifest,
            evidence=[
                Evidence(
                    description="containers without read-only root filesystems",
                    observed=affected,
                    expected=True,
                    source="spec.*Containers[].securityContext.readOnlyRootFilesystem",
                )
            ],
            remediation=Remediation(
                summary="Use a read-only root filesystem and mount writable paths explicitly.",
                iac_patch="securityContext:\n  readOnlyRootFilesystem: true",
                references=[
                    "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"
                ],
            ),
        )
