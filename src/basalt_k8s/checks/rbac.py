"""Kubernetes RBAC and service-account posture checks."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from basalt_core import Evidence, Exposure, Finding, Remediation, Severity

from ..parser import KubernetesManifest
from ..registry import Check, register

if TYPE_CHECKING:  # pragma: no cover
    from ..scanner import KubernetesContext


@register
class RbacWildcardPermissions(Check):
    """Find RBAC rules that use a wildcard verb or resource."""

    rule_id = "rbac.wildcard-permissions"
    title = "RBAC role grants wildcard permissions"
    description = "A Role or ClusterRole grants every verb or every resource in at least one rule."
    severity = Severity.HIGH
    exposure = Exposure.INTERNAL
    control_ids = ("cis-k8s:rbac.least-privilege",)
    kinds = ("Role", "ClusterRole")
    tags = ("kubernetes", "rbac", "least-privilege")

    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        wildcard_rules = self._wildcard_rules(manifest.body.get("rules"))
        if not wildcard_rules:
            return
        yield self.finding(
            manifest,
            evidence=[
                Evidence(
                    description="RBAC rules containing wildcard verbs or resources",
                    observed=wildcard_rules,
                    expected="specific verbs and resource names",
                    source=f"{manifest.kind}.rules",
                )
            ],
            remediation=Remediation(
                summary=(
                    "Replace wildcard verbs and resources with the minimum required permissions."
                ),
                iac_patch=(
                    "rules:\n"
                    '  - apiGroups: [""]\n'
                    '    resources: ["pods"]\n'
                    '    verbs: ["get", "list"]'
                ),
                references=["https://kubernetes.io/docs/concepts/security/rbac-good-practices/"],
            ),
        )

    @staticmethod
    def _wildcard_rules(value: Any) -> list[int]:
        if not isinstance(value, list):
            return []
        matches: list[int] = []
        for index, rule in enumerate(value):
            if not isinstance(rule, dict):
                continue
            verbs = rule.get("verbs")
            resources = rule.get("resources")
            if (isinstance(verbs, list) and "*" in verbs) or (
                isinstance(resources, list) and "*" in resources
            ):
                matches.append(index)
        return matches


@register
class ClusterAdminBinding(Check):
    """Find bindings that grant the cluster-admin ClusterRole."""

    rule_id = "rbac.cluster-admin-binding"
    title = "Binding grants cluster-admin"
    description = "A RoleBinding or ClusterRoleBinding grants the unrestricted cluster-admin role."
    severity = Severity.CRITICAL
    exposure = Exposure.INTERNAL
    control_ids = ("cis-k8s:rbac.no-cluster-admin-binding",)
    kinds = ("RoleBinding", "ClusterRoleBinding")
    tags = ("kubernetes", "rbac", "cluster-admin")

    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        role_ref = manifest.body.get("roleRef")
        if not isinstance(role_ref, dict) or role_ref.get("name") != "cluster-admin":
            return
        yield self.finding(
            manifest,
            evidence=[
                Evidence(
                    description="bound role reference",
                    observed=role_ref,
                    expected="a narrowly scoped Role or ClusterRole",
                    source=f"{manifest.kind}.roleRef",
                )
            ],
            remediation=Remediation(
                summary=(
                    "Bind a minimally privileged role and prefer a namespace-scoped RoleBinding."
                ),
                iac_patch=(
                    "roleRef:\n"
                    "  apiGroup: rbac.authorization.k8s.io\n"
                    "  kind: Role\n"
                    "  name: application-reader"
                ),
                references=["https://kubernetes.io/docs/concepts/security/rbac-good-practices/"],
            ),
        )


@register
class DefaultServiceAccountAutomount(Check):
    """Find default service accounts that do not explicitly disable token automounting."""

    rule_id = "rbac.default-service-account-automount"
    title = "Default ServiceAccount auto-mounts its token"
    description = "The default ServiceAccount does not explicitly disable API token automounting."
    severity = Severity.MEDIUM
    exposure = Exposure.INTERNAL
    control_ids = ("cis-k8s:rbac.default-sa-no-automount",)
    kinds = ("ServiceAccount",)
    tags = ("kubernetes", "rbac", "service-account")

    def run(self, manifest: KubernetesManifest, context: KubernetesContext) -> Iterable[Finding]:
        if manifest.name != "default":
            return
        if manifest.body.get("automountServiceAccountToken") is False:
            return
        yield self.finding(
            manifest,
            evidence=[
                Evidence(
                    description="automountServiceAccountToken",
                    observed=manifest.body.get("automountServiceAccountToken"),
                    expected=False,
                    source="ServiceAccount.automountServiceAccountToken",
                )
            ],
            remediation=Remediation(
                summary="Disable automatic token mounting on the default ServiceAccount.",
                iac_patch="automountServiceAccountToken: false",
                references=["https://kubernetes.io/docs/concepts/security/rbac-good-practices/"],
            ),
        )
