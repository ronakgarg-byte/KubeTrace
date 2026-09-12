# Scope and Limitations — CY-05 Kubernetes RBAC Privilege Path Analyzer

## 1. Overview
The CY-05 Kubernetes RBAC Privilege Path Analyzer is an offline, static security analyzer designed to parse Kubernetes RBAC manifests, model capabilities, build directed privilege escalation graphs, detect privilege-escalation paths leading to administrator-equivalent capability, and compute verified minimal remediations.

---

## 2. In-Scope Privilege Escalation Primitives
In strict adherence to the CY-05 challenge specification, the analyzer implements **only** the following four privilege escalation primitives:

1. **Binding escalation (`Binding escalation`)**:
   - **Mechanism**: A principal has permissions to `create` or `update` a `RoleBinding` (within a target namespace) or `ClusterRoleBinding` (cluster-wide), AND possesses the `bind` verb on the target higher-privilege `Role` or `ClusterRole`.
   - **Conditions**: If the target role is administrator-equivalent (or designated high-privilege role granting wildcard capabilities), the principal achieves cluster administrator equivalence.

2. **Impersonation (`Impersonation`)**:
   - **Mechanism**: A principal possesses the `impersonate` verb on `users`, `groups`, or `serviceaccounts` (matching exact `resourceNames` or wildcard/unrestricted names).
   - **Conditions**: The target principal possesses strictly stronger permissions (evaluated via rule-set superset comparison) or administrator-equivalent capabilities.

3. **Pod/service-account escalation (`Pod/service-account escalation`)**:
   - **Mechanism**: A principal can `create` `pods` in a namespace where an existing `ServiceAccount` possesses stronger or administrator-equivalent capabilities.
   - **Conditions**: By launching a pod configured with `spec.serviceAccountName`, the principal assumes that stronger ServiceAccount's identity and permissions.

4. **Service-account credential access (`Service-account credential access`)**:
   - **Mechanism**: A principal possesses `get`, `list`, or `watch` verbs on `secrets` within a namespace containing a `Secret` of type `kubernetes.io/service-account-token` (or matching annotation `kubernetes.io/service-account.name`).
   - **Conditions**: The target `ServiceAccount` referenced by the token Secret possesses strictly stronger or administrator-equivalent permissions.

---

## 3. Explicitly Out-of-Scope Mechanisms & Simplifying Assumptions

1. **Admission Controllers & Webhooks**:
   - ValidatingAdmissionWebhooks, MutatingAdmissionWebhooks, PodSecurityStandards (PSS), and legacy PodSecurityPolicies (PSP) are **out of scope**.
   - The analyzer assumes any Pod creation permission in a namespace allows mounting any ServiceAccount available in that namespace without admission rejection.

2. **Non-Resource URLs**:
   - Non-resource URLs (e.g., `/healthz`, `/metrics`, `/version`, `/livez`) are parsed and preserved from YAML manifests to prevent parse failures, but are **out of scope** for RBAC privilege escalation path search.

3. **External Authentication & Token Webhooks**:
   - External OIDC, webhook authenticators, and cloud provider IAM bindings (e.g. AWS IAM Roles for Service Accounts - IRSA, GCP Workload Identity, Azure Workload Identity) are out of scope. The analyzer operates solely on static Kubernetes manifests.

4. **Kubelet / Node Capabilities**:
   - Node authorization (`NodeRestriction`), certificate signing requests (`CSR`), and hostPath / volume mount exploits are not modeled as independent escalation primitives outside the four canonical primitives.

5. **Namespace Scoping**:
   - A `RoleBinding` referencing a `ClusterRole` scopes those permissions **strictly to the RoleBinding's namespace**. The analyzer strictly guarantees that permissions from such a binding never leak cluster-wide.

6. **ClusterRole Aggregations**:
   - Aggregated ClusterRoles (`aggregationRule.clusterRoleSelectors`) are resolved statically by matching label selectors against all ClusterRoles in the ingested manifests, with recursion-depth tracking to prevent cycles.

---

## 4. Minimal Remediation Principles
- **Definition of Minimal**:
  - The remediation identifies the single smallest edge (verb, rule, or binding) whose removal severs the detected path while preserving legitimate unrelated permissions.
  - Priority order:
    1. Remove the specific escalation-enabling verb (`bind`, `impersonate`, `create`, `get`, `list`, `watch`) from the specific rule in the role.
    2. If multiple sibling verbs in the same rule enable the primitive, remove all enabling verbs from that rule.
    3. Remove the binding connecting the principal to the role.
- **Automated Virtual Validation**:
  - Every proposed remediation is virtually applied to the capability model and re-tested against the path search engine.
  - A remediation is marked `validated: true` only if re-running path search confirms that the exact escalation path is broken.

---

## 5. Performance and Runtime
- Graph construction and capability indexing are executed once and reused.
- Rule supersets and aggregated roles are cached.
- Path traversal uses cycle-safe Breadth-First Search (BFS) with visited-set history tracking.
- Zero heavyweight C-dependencies: pure Python standard library for graph modeling and traversal, requiring only `PyYAML` for manifest parsing.
