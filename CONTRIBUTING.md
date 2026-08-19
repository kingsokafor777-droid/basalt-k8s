# Contributing

## Setup

```bash
git clone https://github.com/kingsokafor777-droid/basalt-k8s
cd basalt-k8s
make install
make check
```

`make check` runs the CI quality gate: Ruff, mypy in strict mode, and pytest with branch coverage
gated at 80%. Tests must be offline: do not access a cluster, load a kubeconfig, invoke `kubectl`, or
require credentials.

## Adding a check

1. Add the class to the relevant module under `src/basalt_k8s/checks/` and decorate it with
   `@register`.
2. Declare `rule_id`, title, description, severity, control IDs, target Kubernetes kinds, and tags at
   class level. Build output only with `self.finding()`.
3. Every `control_ids` entry must resolve against the `basalt-core` catalogue. Add a missing control to
   Core before adding a rule that references it; the contract test fails otherwise.
4. Interpret only the fields included in scanned YAML. Do not query a cluster, infer an admission policy,
   assume a CNI implementation, resolve Helm values, run Kustomize, or guess about resources absent from
   the source tree.
5. Keep the result attached to the `KubernetesManifest` document location. A check must not construct a
   line location from a guessed YAML path.
6. Exercise both cases with multi-document YAML fixtures: an insecure declaration must emit the expected
   finding, and a hardened declaration must emit none. Add SARIF assertions for new location behavior.
7. For cross-manifest checks, add context behavior and partial-parse-failure coverage. A malformed YAML
   file must not discard findings from healthy files.
8. Document the new rule in the README and update the `[Unreleased]` section of `CHANGELOG.md`.

The parser owns YAML file discovery, safe parsing, parse diagnostics, object identities, and document
locations. The scanner owns cross-manifest context, rule filtering, and partial-failure retention. Checks
own Kubernetes resource semantics. Keep these boundaries intact.

## House rules

- **Offline, always.** Do not call Kubernetes APIs, load kubeconfig, run `kubectl`, execute a subprocess,
  or contact network services from this package. Remediation is data carried on a finding and is never
  executed.
- **Respect manifest scope.** A local manifest set is not a live-cluster inventory. Report only what the
  source establishes, and clearly state when a rule applies only to declared namespaces or objects.
- **Metadata is a public contract.** Rule IDs, resource types, control mappings, severities, source
  locations, and finding identities affect history, SARIF alert identity, and downstream reporting.
- **Use Kubernetes documentation.** Link each rule's semantics to authoritative Kubernetes documentation,
  not a deployment-specific assumption.
- **Severity is impact; exposure and exploitability express reachability.** Do not inflate a severity
  merely to raise a risk score.
- **Descriptions explain consequence, not only configuration.** Remediation should be specific and
  reviewable but must never be applied by this package.

## Changing a `rule_id`

Changing a rule identifier is breaking because `Finding.fingerprint` derives from it. A rename orphans the
rule's historical observations in every downstream warehouse and may create a new Code Scanning alert.
Open an issue first and update `CHANGELOG.md` when an approved breaking change is made.

## Commits

Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Update the `[Unreleased]` section
of `CHANGELOG.md` for every user-visible change.
