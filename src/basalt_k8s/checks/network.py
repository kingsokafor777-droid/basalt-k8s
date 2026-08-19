"""Kubernetes NetworkPolicy posture checks."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from basalt_core import Evidence, Exposure, Finding, Remediation, Severity

from ..parser import KubernetesManifest
from ..registry import Check, register

if TYPE_CHECKING:  # pragma: no cover
    from ..scanner import KubernetesContext


@register
class NamespaceDefaultDenyNetworkPolicy(Check):
    """Find declared namespaces without a default-deny policy in the scanned manifests."""

    rule_id = "network.namespace-default-deny-missing"
    title = "Namespace lacks a default-deny NetworkPolicy"
    description = (
        "No manifest-defined NetworkPolicy selects all Pods and denies both ingress and egress "
        "by default."
    )
    severity = Severity.HIGH
    exposure = Exposure.INTERNAL
    control_ids = ("cis-k8s:network.default-deny",)
    kinds = ("Namespace",)
    tags = ("kubernetes", "network-policy", "default-deny")

    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        if context.has_default_deny_network_policy(manifest.name):
            return
        yield self.finding(
            manifest,
            evidence=[
                Evidence(
                    description="manifest-defined default deny coverage",
                    observed=False,
                    expected=True,
                    source="NetworkPolicy manifests in namespace",
                )
            ],
            remediation=Remediation(
                summary=(
                    "Add a NetworkPolicy that selects all Pods and defines empty ingress "
                    "and egress allow lists."
                ),
                iac_patch=(
                    "apiVersion: networking.k8s.io/v1\n"
                    "kind: NetworkPolicy\n"
                    "metadata:\n"
                    f"  namespace: {manifest.name}\n"
                    "  name: default-deny-all\n"
                    "spec:\n"
                    "  podSelector: {}\n"
                    "  policyTypes: [Ingress, Egress]"
                ),
                references=[
                    "https://kubernetes.io/docs/concepts/services-networking/network-policies/"
                ],
            ),
        )
