# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changing a `rule_id` is breaking: it orphans that check's history in any downstream
warehouse because `Finding.fingerprint` is derived from it.

## [Unreleased]

## [0.1.0] - 2026-08-18

Initial release. Eight offline Kubernetes posture checks across RBAC, Pod Security, and
NetworkPolicy manifest declarations.

### Added

- Safe multi-document YAML parser with deterministic recursive discovery, `kind: List` support,
  Kubernetes object identities, and YAML-document locations for SARIF.
- **RBAC** checks for wildcard permissions, `cluster-admin` bindings, and default ServiceAccounts
  that do not explicitly disable API token automounting.
- **Pod Security** checks for privileged containers, host namespace sharing, missing non-root
  execution, and missing read-only root filesystem declarations on standard workload templates.
- **NetworkPolicy** check for declared namespaces without a manifest-defined default-deny policy
  covering both ingress and egress.
- Declarative `Check` registry that rejects incomplete and duplicate rule identifiers at import time
  and validates every shared control mapping against the Basalt Core catalogue in tests.
- `basalt-k8s` CLI with `scan`, `checks`, SARIF default output, alternate Basalt/OCSF/JSONL emitters,
  output files, deduplication, and `--fail-on` CI gating.
- `basalt.scanners` entry point under the `k8s` alias, verified by a contract test against Basalt Core
  discovery.
- Offline tests for YAML parsing, RBAC and workload decisions, cross-manifest default-deny coverage,
  source locations, SARIF, CLI behavior, partial parse failures, and plugin compatibility.

### Notes

- Requires `basalt-core>=0.1.1,<1` and `PyYAML>=6.0,<7`.
- The scanner does not contact a Kubernetes API server, load kubeconfig, execute `kubectl`, or apply
  a manifest.
- Helm rendering, Kustomize overlays, Custom Resources, live-cluster state, admission controls, CNI
  enforcement, and remediation are out of scope for this initial release.

[Unreleased]: https://github.com/kingsokafor777-droid/basalt-k8s/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kingsokafor777-droid/basalt-k8s/releases/tag/v0.1.0
