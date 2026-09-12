"""
capability_model.py - Kubernetes RBAC Capability Model

Defines dataclasses for RBAC principals, roles, bindings, rules, and secrets.
Implements:
- ServiceAccount, User, and Group identity normalization
- Aggregated ClusterRole resolution
- Scoped rule sets (RoleBinding namespace scoping vs ClusterRoleBinding)
- Wildcard expansion and matching
- Rule-set comparison ("stronger" permission checks)
- Terminal administrator-equivalent capability detection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class Principal:
    """Canonical representation of a Kubernetes subject/principal."""
    kind: str  # "ServiceAccount", "User", "Group"
    name: str
    namespace: Optional[str] = None  # None for Users and Groups, or cluster-scoped

    @property
    def canonical_id(self) -> str:
        """
        Returns the standard Kubernetes identity string:
        - ServiceAccount: system:serviceaccount:<namespace>:<name>
        - User: User:<name>
        - Group: Group:<name>
        """
        k = self.kind.strip()
        if k.lower() == "serviceaccount":
            ns = self.namespace or "default"
            return f"system:serviceaccount:{ns}:{self.name}"
        elif k.lower() == "user":
            return f"User:{self.name}"
        elif k.lower() == "group":
            return f"Group:{self.name}"
        return f"{k}:{self.name}"

    @classmethod
    def from_subject_dict(cls, subj: Dict[str, Any], default_ns: Optional[str] = None) -> Principal:
        kind = subj.get("kind", "User")
        name = subj.get("name", "")
        ns = subj.get("namespace")
        if kind.lower() == "serviceaccount":
            if not ns:
                ns = default_ns or "default"
        return cls(kind=kind, name=name, namespace=ns)


@dataclass(frozen=True)
class PolicyRule:
    """Representation of an RBAC PolicyRule within a Role or ClusterRole."""
    api_groups: Tuple[str, ...] = ("*",)
    resources: Tuple[str, ...] = ("*",)
    verbs: Tuple[str, ...] = ("*",)
    resource_names: Tuple[str, ...] = ()
    non_resource_urls: Tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> PolicyRule:
        api_groups = tuple(d.get("apiGroups") or ["*"])
        resources = tuple(d.get("resources") or ["*"])
        verbs = tuple(d.get("verbs") or ["*"])
        resource_names = tuple(d.get("resourceNames") or [])
        non_resource_urls = tuple(d.get("nonResourceURLs") or [])
        return cls(
            api_groups=api_groups,
            resources=resources,
            verbs=verbs,
            resource_names=resource_names,
            non_resource_urls=non_resource_urls,
        )

    def allows_verb(self, verb: str) -> bool:
        if "*" in self.verbs:
            return True
        return verb.lower() in [v.lower() for v in self.verbs]

    def allows_api_group(self, api_group: str) -> bool:
        if "*" in self.api_groups:
            return True
        return api_group in self.api_groups

    def allows_resource(self, resource: str) -> bool:
        if "*" in self.resources:
            return True
        res_lower = resource.lower()
        for r in self.resources:
            r_lower = r.lower()
            if r_lower == "*" or r_lower == res_lower:
                return True
            if r_lower.endswith("/*"):
                prefix = r_lower[:-2]
                if res_lower.startswith(prefix + "/"):
                    return True
        return False

    def allows_resource_name(self, resource_name: Optional[str]) -> bool:
        if not self.resource_names:
            return True  # Empty means all names permitted
        if resource_name is None:
            return True
        return resource_name in self.resource_names


@dataclass(frozen=True)
class ScopedRule:
    """An effective rule bound to a principal in a specific namespace (or cluster-wide)."""
    rule: PolicyRule
    namespace: Optional[str]  # None indicates cluster-wide
    source_binding_name: str
    source_binding_kind: str  # "RoleBinding" or "ClusterRoleBinding"
    source_role_name: str
    source_role_kind: str  # "Role" or "ClusterRole"
    rule_index: int

    def matches(
        self,
        verb: str,
        resource: str,
        api_group: str = "",
        namespace: Optional[str] = None,
        resource_name: Optional[str] = None,
        cluster_scoped: bool = False,
    ) -> bool:
        # Cluster-scoped resources require cluster-wide rule
        if cluster_scoped and self.namespace is not None:
            return False

        # If a target namespace is specified for a namespaced resource:
        # - Cluster-wide rule (self.namespace is None) matches any namespace.
        # - Namespaced rule matches only if it is in the exact same namespace.
        if namespace is not None and self.namespace is not None:
            if self.namespace != namespace:
                return False

        if not self.rule.allows_api_group(api_group):
            return False
        if not self.rule.allows_resource(resource):
            return False
        if not self.rule.allows_verb(verb):
            return False
        if not self.rule.allows_resource_name(resource_name):
            return False

        return True


@dataclass
class RoleObject:
    """Model of a Role or ClusterRole."""
    name: str
    namespace: Optional[str]  # None for ClusterRole
    is_cluster_role: bool
    rules: List[PolicyRule] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    aggregation_rule: Optional[Dict[str, Any]] = None
    origin_file: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any], is_cluster_role: bool) -> RoleObject:
        metadata = d.get("metadata") or {}
        name = metadata.get("name", "")
        ns = None if is_cluster_role else (metadata.get("namespace") or "default")
        labels = metadata.get("labels") or {}
        annotations = metadata.get("annotations") or {}
        rules = [PolicyRule.from_dict(r) for r in (d.get("rules") or [])]
        agg_rule = d.get("aggregationRule") if is_cluster_role else None
        return cls(
            name=name,
            namespace=ns,
            is_cluster_role=is_cluster_role,
            rules=rules,
            labels=labels,
            annotations=annotations,
            aggregation_rule=agg_rule,
            origin_file=d.get("_origin_file"),
        )


@dataclass
class BindingObject:
    """Model of a RoleBinding or ClusterRoleBinding."""
    name: str
    namespace: Optional[str]  # None for ClusterRoleBinding
    is_cluster_binding: bool
    role_ref_kind: str
    role_ref_name: str
    role_ref_api_group: str
    subjects: List[Principal] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    origin_file: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any], is_cluster_binding: bool) -> BindingObject:
        metadata = d.get("metadata") or {}
        name = metadata.get("name", "")
        ns = None if is_cluster_binding else (metadata.get("namespace") or "default")
        labels = metadata.get("labels") or {}
        annotations = metadata.get("annotations") or {}
        role_ref = d.get("roleRef") or {}
        role_ref_kind = role_ref.get("kind", "ClusterRole")
        role_ref_name = role_ref.get("name", "")
        role_ref_api_group = role_ref.get("apiGroup", "rbac.authorization.k8s.io")

        subjects_raw = d.get("subjects") or []
        subjects = [Principal.from_subject_dict(s, default_ns=ns) for s in subjects_raw]

        return cls(
            name=name,
            namespace=ns,
            is_cluster_binding=is_cluster_binding,
            role_ref_kind=role_ref_kind,
            role_ref_name=role_ref_name,
            role_ref_api_group=role_ref_api_group,
            subjects=subjects,
            labels=labels,
            annotations=annotations,
            origin_file=d.get("_origin_file"),
        )


@dataclass
class SecretObject:
    """Model of a Kubernetes Secret, specifically for ServiceAccount tokens."""
    name: str
    namespace: str
    secret_type: str
    service_account_name: Optional[str] = None
    annotations: Dict[str, str] = field(default_factory=dict)
    origin_file: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> SecretObject:
        metadata = d.get("metadata") or {}
        name = metadata.get("name", "")
        ns = metadata.get("namespace") or "default"
        sec_type = d.get("type") or ""
        annotations = metadata.get("annotations") or {}

        # Look up referenced service account name
        sa_name = annotations.get("kubernetes.io/service-account.name")
        return cls(
            name=name,
            namespace=ns,
            secret_type=sec_type,
            service_account_name=sa_name,
            annotations=annotations,
            origin_file=d.get("_origin_file"),
        )

    def is_service_account_token_for(self) -> Optional[str]:
        """Returns the canonical ID of the SA this token authenticates as, if any."""
        sa_token_type = "kubernetes.io/service-account-token"
        if self.secret_type == sa_token_type or self.service_account_name:
            if self.service_account_name:
                return f"system:serviceaccount:{self.namespace}:{self.service_account_name}"
        return None


@dataclass
class ServiceAccountObject:
    """Model of a Kubernetes ServiceAccount."""
    name: str
    namespace: str
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    origin_file: Optional[str] = None

    @property
    def canonical_id(self) -> str:
        return f"system:serviceaccount:{self.namespace}:{self.name}"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> ServiceAccountObject:
        metadata = d.get("metadata") or {}
        return cls(
            name=metadata.get("name", ""),
            namespace=metadata.get("namespace") or "default",
            labels=metadata.get("labels") or {},
            annotations=metadata.get("annotations") or {},
            origin_file=d.get("_origin_file"),
        )


def _matches_label_selector(labels: Dict[str, str], selector: Dict[str, Any]) -> bool:
    """Checks if labels dictionary satisfies a Kubernetes label selector."""
    match_labels = selector.get("matchLabels") or {}
    for k, v in match_labels.items():
        if labels.get(k) != v:
            return False

    match_exprs = selector.get("matchExpressions") or []
    for expr in match_exprs:
        key = expr.get("key")
        op = expr.get("operator")
        values = expr.get("values") or []
        val_in_labels = labels.get(key)

        if op == "In":
            if val_in_labels not in values:
                return False
        elif op == "NotIn":
            if val_in_labels in values:
                return False
        elif op == "Exists":
            if key not in labels:
                return False
        elif op == "DoesNotExist":
            if key in labels:
                return False

    return True


class RBACCapabilityModel:
    """
    Resolved RBAC capability model.
    Resolves ClusterRole aggregations, binds rules to principals with proper
    namespace scoping, and indexes effective capabilities per principal.
    """

    def __init__(self) -> None:
        self.roles: Dict[Tuple[str, Optional[str]], RoleObject] = {}  # (name, ns) -> RoleObject
        self.cluster_roles: Dict[str, RoleObject] = {}  # name -> RoleObject
        self.role_bindings: List[BindingObject] = []
        self.cluster_role_bindings: List[BindingObject] = []
        self.service_accounts: Dict[str, ServiceAccountObject] = {}  # canonical_id -> SA
        self.secrets: List[SecretObject] = []

        # Derived mappings
        self.principal_scoped_rules: Dict[str, List[ScopedRule]] = {}  # canonical_id -> list[ScopedRule]
        self.all_principals: Set[str] = set()

    def add_role(self, role: RoleObject) -> None:
        if role.is_cluster_role:
            self.cluster_roles[role.name] = role
        else:
            self.roles[(role.name, role.namespace)] = role

    def add_binding(self, binding: BindingObject) -> None:
        if binding.is_cluster_binding:
            self.cluster_role_bindings.append(binding)
        else:
            self.role_bindings.append(binding)
        for s in binding.subjects:
            self.all_principals.add(s.canonical_id)

    def add_service_account(self, sa: ServiceAccountObject) -> None:
        self.service_accounts[sa.canonical_id] = sa
        self.all_principals.add(sa.canonical_id)

    def add_secret(self, sec: SecretObject) -> None:
        self.secrets.append(sec)

    def resolve_cluster_role_aggregations(self) -> None:
        """
        Resolves aggregationRule in ClusterRoles by merging matching ClusterRoles' rules.
        Handles nested aggregations with cycle protection.
        """
        visited: Set[str] = set()

        def get_aggregated_rules(cr_name: str, path: Set[str]) -> List[PolicyRule]:
            if cr_name in path:
                return []  # Break aggregation cycle
            cr = self.cluster_roles.get(cr_name)
            if not cr:
                return []

            if not cr.aggregation_rule:
                return cr.rules

            merged_rules = list(cr.rules)
            selectors = cr.aggregation_rule.get("clusterRoleSelectors") or []
            new_path = path | {cr_name}

            for other_name, other_cr in self.cluster_roles.items():
                if other_name == cr_name:
                    continue
                matches_any = False
                for sel in selectors:
                    if _matches_label_selector(other_cr.labels, sel):
                        matches_any = True
                        break
                if matches_any:
                    merged_rules.extend(get_aggregated_rules(other_name, new_path))

            return merged_rules

        for name, cr in list(self.cluster_roles.items()):
            if cr.aggregation_rule:
                cr.rules = get_aggregated_rules(name, set())

    def bind_rules_to_principals(self) -> None:
        """
        Binds rules from roles to principals based on RoleBindings and ClusterRoleBindings.
        Enforces:
        - ClusterRoleBinding: rules are cluster-wide (namespace=None).
        - RoleBinding referencing Role: rules scoped to RoleBinding namespace.
        - RoleBinding referencing ClusterRole: rules scoped strictly to RoleBinding namespace!
        """
        self.principal_scoped_rules.clear()

        # Process ClusterRoleBindings
        for crb in self.cluster_role_bindings:
            cr = self.cluster_roles.get(crb.role_ref_name)
            if not cr:
                continue
            for idx, r in enumerate(cr.rules):
                scoped = ScopedRule(
                    rule=r,
                    namespace=None,  # Cluster-wide
                    source_binding_name=crb.name,
                    source_binding_kind="ClusterRoleBinding",
                    source_role_name=cr.name,
                    source_role_kind="ClusterRole",
                    rule_index=idx,
                )
                for subj in crb.subjects:
                    cid = subj.canonical_id
                    self.principal_scoped_rules.setdefault(cid, []).append(scoped)
                    self.all_principals.add(cid)

        # Process RoleBindings
        for rb in self.role_bindings:
            rb_ns = rb.namespace or "default"
            role_rules: List[PolicyRule] = []
            role_kind = rb.role_ref_kind
            role_name = rb.role_ref_name

            if role_kind == "ClusterRole":
                cr = self.cluster_roles.get(role_name)
                if cr:
                    role_rules = cr.rules
            else:
                role = self.roles.get((role_name, rb_ns))
                if role:
                    role_rules = role.rules

            for idx, r in enumerate(role_rules):
                scoped = ScopedRule(
                    rule=r,
                    namespace=rb_ns,  # Scoped strictly to RoleBinding's namespace!
                    source_binding_name=rb.name,
                    source_binding_kind="RoleBinding",
                    source_role_name=role_name,
                    source_role_kind=role_kind,
                    rule_index=idx,
                )
                for subj in rb.subjects:
                    cid = subj.canonical_id
                    self.principal_scoped_rules.setdefault(cid, []).append(scoped)
                    self.all_principals.add(cid)

    def is_admin_equivalent_role(self, role: RoleObject) -> bool:
        """
        Checks if a role has administrator-equivalent capability:
        verbs: ["*"] and resources: ["*"] (with matching apiGroups wildcard).
        """
        for r in role.rules:
            if "*" in r.verbs and "*" in r.resources and ("*" in r.api_groups or "" in r.api_groups):
                return True
        return False

    def is_admin_equivalent(self, principal_id: str) -> bool:
        """
        Checks if principal directly has cluster-wide administrator-equivalent capability:
        verbs: ["*"], resources: ["*"], apiGroups: ["*"] cluster-wide.
        """
        rules = self.principal_scoped_rules.get(principal_id, [])
        for sr in rules:
            if sr.namespace is None:  # Cluster-wide
                r = sr.rule
                if "*" in r.verbs and "*" in r.resources and ("*" in r.api_groups or "" in r.api_groups):
                    return True
        return False

    def principal_has_permission(
        self,
        principal_id: str,
        verb: str,
        resource: str,
        api_group: str = "",
        namespace: Optional[str] = None,
        resource_name: Optional[str] = None,
    ) -> List[ScopedRule]:
        """
        Returns all ScopedRules of a principal granting the requested permission.
        """
        matching: List[ScopedRule] = []
        rules = self.principal_scoped_rules.get(principal_id, [])
        for sr in rules:
            if sr.matches(verb=verb, resource=resource, api_group=api_group, namespace=namespace, resource_name=resource_name):
                matching.append(sr)
        return matching

    def is_stronger_principal(self, candidate_id: str, source_id: str) -> bool:
        """
        Determines if candidate_id is 'stronger' than source_id.
        Requirement: candidate's permission set is NOT a subset of source's permission set.
        """
        if candidate_id == source_id:
            return False

        candidate_rules = self.principal_scoped_rules.get(candidate_id, [])
        if not candidate_rules:
            return False

        # If candidate is admin and source is not, candidate is stronger
        cand_admin = self.is_admin_equivalent(candidate_id)
        src_admin = self.is_admin_equivalent(source_id)
        if cand_admin and not src_admin:
            return True
        if src_admin:
            # An admin cannot escalate to someone stronger
            return False

        source_rules = self.principal_scoped_rules.get(source_id, [])
        if not source_rules:
            return True  # Candidate has permissions, source has none

        # For every rule in candidate, check if it's completely covered by source's rules
        for cr in candidate_rules:
            c_rule = cr.rule
            c_ns = cr.namespace
            rule_covered = False

            for sr in source_rules:
                s_rule = sr.rule
                s_ns = sr.namespace

                # Check namespace coverage
                if s_ns is not None:
                    if c_ns is None or s_ns != c_ns:
                        continue

                # Check verbs coverage
                if "*" not in s_rule.verbs:
                    if "*" in c_rule.verbs:
                        continue
                    if not set(c_rule.verbs).issubset(set(s_rule.verbs)):
                        continue

                # Check resources coverage
                if "*" not in s_rule.resources:
                    if "*" in c_rule.resources:
                        continue
                    # Check each resource in candidate
                    all_res_covered = True
                    for cres in c_rule.resources:
                        if not any(
                            sres == "*" or sres == cres or (sres.endswith("/*") and cres.startswith(sres[:-2] + "/"))
                            for sres in s_rule.resources
                        ):
                            all_res_covered = False
                            break
                    if not all_res_covered:
                        continue

                # Check apiGroups coverage
                if "*" not in s_rule.api_groups:
                    if "*" in c_rule.api_groups:
                        continue
                    if not set(c_rule.api_groups).issubset(set(s_rule.api_groups)):
                        continue

                # Check resourceNames coverage
                if s_rule.resource_names:
                    if not c_rule.resource_names:
                        continue
                    if not set(c_rule.resource_names).issubset(set(s_rule.resource_names)):
                        continue

                # If all components covered, this candidate rule is subsumed
                rule_covered = True
                break

            if not rule_covered:
                return True

        return False
