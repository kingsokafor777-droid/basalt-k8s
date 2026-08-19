# Basalt Kubernetes

**Basalt Kubernetes** is a deterministic, offline posture scanner for local Kubernetes YAML manifests. It evaluates **RBAC**, **Pod Security Standards**, and **NetworkPolicy** declarations, then emits normalized Basalt results as **SARIF 2.1.0**, Basalt JSON, OCSF, or JSONL. SARIF is the default so findings can be uploaded to GitHub Code Scanning.

> The scanner never contacts a Kubernetes API server, runs `kubectl`, loads a kubeconfig, or applies a manifest. It parses local YAML with `yaml.safe_load_all`, making it suitable for pull-request and pre-merge checks without cluster credentials.

Kubernetes RBAC guidance recommends least privilege, avoiding wildcard permissions and unnecessary `cluster-admin` access, and disabling automatic ServiceAccount token mounting when it is not required.[1] The Kubernetes Pod Security Standards define baseline and restricted controls for host namespaces, privileged containers, and non-root execution.[2]

## Install

```bash
pip install "basalt-core @ git+https://github.com/kingsokafor777-droid/basalt-core@main"
pip install basalt-k8s
```

For a repository checkout:

```bash
make install
make check
```

## Scan Kubernetes Manifests

```bash
# SARIF is the default; recursively scan the current directory.
basalt-k8s scan . --output results.sarif --fail-on high

# Inspect every check and its Basalt Core control mapping.
basalt-k8s checks --verbose

# Run one rule and emit the lossless Basalt document to stdout.
basalt-k8s scan manifests/ \
  --rule pod.privileged-container \
  --format basalt
```

The process returns status **1** only when `--fail-on` is set and a finding meets the selected threshold. Configuration errors, such as an unknown rule identifier, return status **2**. An invalid YAML file is recorded in Basalt scan metadata while parseable files continue to be analyzed.

| Capability | Behavior |
|---|---|
| Inputs | One or more `.yaml` or `.yml` files or directories, recursively scanned. `.git`, virtual environments, and `node_modules` are skipped. |
| Evaluation | Offline, multi-document YAML parsing only. No cluster, kubeconfig, credential, network, subprocess, or mutation operation is used. |
| Locations | Each finding maps to the YAML document containing the Kubernetes object and is emitted as a SARIF physical location. |
| Output | `sarif` (default), `basalt`, `ocsf`, and `jsonl` through Basalt Core emitters. |
| Credentials | None. The scanner does not authenticate to Kubernetes or any cloud provider. |

## Initial Rule Catalogue

The initial release concentrates on common privilege-escalation paths, baseline Pod Security controls, restricted workload hardening, and manifest-defined namespace isolation. All shared control identifiers are validated against `basalt-core` in the test suite.

| Rule ID | Kubernetes resource | Trigger | Severity | Shared control |
|---|---|---|---|---|
| `rbac.wildcard-permissions` | `Role`, `ClusterRole` | A rule includes `*` in `verbs` or `resources` | High | `cis-k8s:rbac.least-privilege` |
| `rbac.cluster-admin-binding` | `RoleBinding`, `ClusterRoleBinding` | `roleRef.name` is `cluster-admin` | Critical | `cis-k8s:rbac.no-cluster-admin-binding` |
| `rbac.default-service-account-automount` | `ServiceAccount` | The `default` account does not set `automountServiceAccountToken: false` | Medium | `cis-k8s:rbac.default-sa-no-automount` |
| `pod.privileged-container` | Standard Pod workloads | A regular, init, or ephemeral container sets `privileged: true` | Critical | `cis-k8s:pod.no-privileged` |
| `pod.host-namespaces-enabled` | Standard Pod workloads | `hostNetwork`, `hostPID`, or `hostIPC` is true | High | `cis-k8s:pod.no-host-namespaces` |
| `pod.run-as-non-root-missing` | Linux Pod workloads | A container lacks effective `runAsNonRoot: true` | High | `cis-k8s:pod.run-as-non-root` |
| `pod.read-only-root-filesystem-missing` | Linux Pod workloads | A container lacks `readOnlyRootFilesystem: true` | Medium | `cis-k8s:pod.read-only-root-fs` |
| `network.namespace-default-deny-missing` | Declared `Namespace` | No scanned NetworkPolicy selects all Pods and denies both ingress and egress | High | `cis-k8s:network.default-deny` |

The Pod Security rules inspect `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `Job`, and `CronJob` Pod templates. The default-deny check reports only **declared Namespace manifests**; it does not guess about namespaces outside the scanned source tree. Kubernetes NetworkPolicy documentation explains that an empty `podSelector` selects every Pod in a namespace and that a policy can explicitly isolate both ingress and egress.[3]

## GitHub Code Scanning

Basalt Core's SARIF emitter adds stable partial fingerprints, rule metadata, severity, controls, and YAML file locations. GitHub supports uploading SARIF from third-party analyzers using `github/codeql-action/upload-sarif`.[4]

Create `.github/workflows/basalt-k8s.yml` in the repository containing Kubernetes manifests:

```yaml
name: Basalt Kubernetes

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  kubernetes-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install basalt-k8s
      - run: basalt-k8s scan . --output results.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: results.sarif
          category: basalt-k8s
```

The scanner writes SARIF before applying the optional severity gate. This permits Code Scanning to receive the findings even when the workflow intentionally fails the pull request for policy enforcement.

## Architecture

```text
Kubernetes YAML manifests
       │
       ▼
Safe multi-document YAML parser ──► API objects + document locations
       │
       ▼
RBAC / Pod Security / NetworkPolicy checks ──► normalized Basalt Findings
       │
       ├──► Basalt / OCSF / JSONL
       └──► SARIF 2.1.0 ──► GitHub Code Scanning
```

The package registers itself in `basalt.scanners` under `k8s`, making it discoverable through the shared Basalt plugin interface.

## Development

```bash
make format     # safe lint fixes and formatting
make check      # Ruff, strict mypy, pytest, branch-aware coverage
make checks     # display the check catalogue
make build      # build sdist and wheel
```

The offline test suite covers multi-document parsing, YAML source locations, local directory discovery, RBAC and workload rule decisions, NetworkPolicy cross-manifest behavior, partial parse failures, SARIF output, CLI behavior, and Basalt Core plugin discovery.

## Scope and Intentional Non-Goals

Basalt Kubernetes scans **local source manifests** only. It does not query cluster state, inspect Helm templates after rendering, evaluate Kustomize overlays, resolve external references, inspect Custom Resource Definitions, check admission-controller configuration, or determine whether a cluster network plugin enforces NetworkPolicy. A default-deny policy has practical effect only with a NetworkPolicy-capable networking implementation.[3]

The source parser accepts standard YAML documents and `kind: List` objects. It intentionally excludes imperative operations, `kubectl`, live-cluster inventory, remediation, credentials, scheduling, and persistence. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/research_sources.md](docs/research_sources.md) for more detail.

## References

[1]: https://kubernetes.io/docs/concepts/security/rbac-good-practices/ "Kubernetes RBAC Good Practices"
[2]: https://kubernetes.io/docs/concepts/security/pod-security-standards/ "Kubernetes Pod Security Standards"
[3]: https://kubernetes.io/docs/concepts/services-networking/network-policies/ "Kubernetes Network Policies"
[4]: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file "GitHub: Uploading a SARIF file"
