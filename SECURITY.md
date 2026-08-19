# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Report privately through [GitHub private vulnerability reporting](https://github.com/kingsokafor777-droid/basalt-k8s/security/advisories/new), not a public issue. Include the affected version, minimal reproduction steps, and the security impact. Expect acknowledgement within 72 hours and an initial assessment within seven days.

## This scanner is offline and non-mutating

`basalt-k8s` does not contact a Kubernetes API server, read kubeconfig, invoke `kubectl`, execute a subprocess, apply a manifest, or make a network call during scanning. It reads local YAML with safe parsing and emits findings as data. The package must not gain behavior that loads external cluster state, evaluates untrusted code, or performs remediation.

Remediation is declarative data attached to each finding for a human or a reviewed downstream workflow. This package must never alter source manifests or Kubernetes resources.

## Scan output is sensitive

The scanner uses no credentials, but its **output is not harmless**. A scan result maps potentially exploitable Kubernetes configuration and can include workload names, namespaces, cluster-role bindings, source paths, image references, and security settings.

- Do not commit scan output to a public repository. The `.gitignore` excludes `results.sarif` and common findings files for this reason.
- Treat CI artifacts as sensitive. Do not attach results to public workflow runs without a deliberate review.
- SARIF uploaded to GitHub Code Scanning inherits the repository's visibility and access controls.
- Do not add actual credentials, tokens, production endpoints, or customer data to test fixtures.

## Parser and dependency handling

The analyzer processes configuration authored by users. Treat all source input as untrusted data. Do not add custom YAML constructors, unsafe loaders, template execution, dynamic module loading, shell-outs, or live-cluster deserialization without a documented threat model and offline test suite.

PyYAML and Basalt Core are third-party dependencies. Report dependency vulnerabilities upstream and open a private advisory here if a dependency interaction creates a Basalt Kubernetes-specific impact.

## Out of scope

- Correctness of compliance mappings. Basalt Core control catalogues are non-authoritative seed subsets until benchmark revisions are pinned.
- A false negative or false positive in a check. These are product defects; open an issue with a minimal reproducible Kubernetes manifest.
- Live-cluster state, kubeconfig, Helm rendering, Kustomize overlays, CNI enforcement, admission policy state, CRD-specific semantics, and behavior not explicitly supported by the documented scanner scope.
