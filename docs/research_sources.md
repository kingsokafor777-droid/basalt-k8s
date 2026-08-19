# Design References

The initial Basalt Kubernetes scanner is grounded in these public references.

| Topic | Source | Relevance |
|---|---|---|
| RBAC good practice | [Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) | Recommends least privilege, avoiding wildcard access and unnecessary `cluster-admin` usage, and disabling automatic ServiceAccount token mounting where possible. |
| Pod Security Standards | [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) | Documents baseline restrictions for privileged containers and host namespaces, and restricted requirements for non-root execution. |
| NetworkPolicy | [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) | Documents default allow behavior and default-deny policies using an empty Pod selector and ingress/egress isolation. |
| Code Scanning | [Uploading a SARIF file to GitHub](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file) | Documents uploading third-party SARIF with `github/codeql-action/upload-sarif`. |

These sources guide initial check semantics and documentation. Basalt Core control mappings remain non-authoritative seed mappings until benchmark versions are explicitly pinned.
