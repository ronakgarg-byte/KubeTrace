# CY-05 Kubernetes RBAC Privilege Path Analyzer

Offline static analyzer in Python that ingests Kubernetes RBAC YAML manifests, constructs a capability and escalation graph, discovers privilege-escalation paths using strictly four defined escalation primitives, computes validated minimal remediations, and outputs a standardized JSON report.

---

## Quickstart in VS Code

### 1. Open Terminal in VS Code
Press ``Ctrl + ` `` to open the integrated terminal in VS Code.

### 2. Run the Analyzer
Analyze any manifest or folder:
```powershell
uv run python main.py tests/dev_bundles/escalation_combined.yaml -o sample_report.json
```
Or using python directly:
```powershell
.venv\Scripts\python.exe main.py tests/dev_bundles/escalation_combined.yaml -o sample_report.json
```

### 3. Run Tests
```powershell
uv run python -m unittest discover tests
```

### 4. Run & Debug with F5
Pre-configured debugging profiles are in `.vscode/launch.json`:
- **Python: Run Analyzer on Combined Bundle**
- **Python: Run Analyzer (Interactive)**
- **Python: Run All Unit Tests**

---

## In-Scope Escalation Primitives
1. **Binding escalation**: Principal can `create`/`update` a `RoleBinding`/`ClusterRoleBinding` and has `bind` on higher-privilege `Role`/`ClusterRole`.
2. **Impersonation**: Principal has `impersonate` verb on `users`, `groups`, or `serviceaccounts` with stronger permissions.
3. **Pod/service-account escalation**: Principal can `create` `pods` in a namespace where a stronger `ServiceAccount` exists.
4. **Service-account credential access**: Principal can `get`/`list`/`watch` a `Secret` that is a `ServiceAccount` token for a stronger `ServiceAccount`.

---

## Output Schema
Each reported path includes:
- `source_principal`: Canonical subject ID (e.g. `system:serviceaccount:default:sa0`)
- `traversed_objects`: Ordered YAML object names traversed
- `escalation_primitive`: One of the 4 exact primitive names
- `terminal_capability`: Terminal administrator-equivalent capability
- `remediation`: Validated minimal permission removal (`remove_verb`, `remove_rule`, `remove_binding`)
