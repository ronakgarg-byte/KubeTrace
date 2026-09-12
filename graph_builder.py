"""
graph_builder.py - RBAC Capability and Escalation Graph Builder

Builds a directed graph representing principal-to-principal and principal-to-admin
escalation edges using strictly the four defined escalation primitives:
1. Binding escalation
2. Impersonation
3. Pod/service-account escalation
4. Service-account credential access
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from capability_model import (
    PolicyRule,
    RBACCapabilityModel,
    RoleObject,
    ScopedRule,
)

# Constant terminal node for administrator-equivalent capability
ADMIN_TERMINAL = "CAPABILITY:ADMIN_EQUIVALENT"

# Exact primitive names required by specification
PRIMITIVE_BINDING_ESCALATION = "Binding escalation"
PRIMITIVE_IMPERSONATION = "Impersonation"
PRIMITIVE_POD_SA_ESCALATION = "Pod/service-account escalation"
PRIMITIVE_CREDENTIAL_ACCESS = "Service-account credential access"


@dataclass(frozen=True)
class EscalationEdge:
    """Directed edge in the privilege escalation graph."""
    source: str
    target: str
    primitive: str
    traversed_objects: Tuple[str, ...]
    enabling_binding: Optional[str] = None
    enabling_binding_kind: Optional[str] = None
    enabling_role: Optional[str] = None
    enabling_role_kind: Optional[str] = None
    enabling_rule_index: Optional[int] = None
    enabling_verb: Optional[str] = None
    enabling_verbs: Tuple[str, ...] = ()
    remediation_candidate: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "primitive": self.primitive,
            "traversed_objects": list(self.traversed_objects),
            "remediation_candidate": self.remediation_candidate,
        }


class RBACGraph:
    """Directed graph of principals and escalation edges."""

    def __init__(self) -> None:
        self.nodes: Set[str] = set()
        self.adjacency: Dict[str, List[EscalationEdge]] = {}

    def add_node(self, node: str) -> None:
        self.nodes.add(node)
        self.adjacency.setdefault(node, [])

    def add_edge(self, edge: EscalationEdge) -> None:
        self.add_node(edge.source)
        self.add_node(edge.target)
        # Avoid duplicate identical edges
        for existing in self.adjacency[edge.source]:
            if (
                existing.target == edge.target
                and existing.primitive == edge.primitive
                and existing.traversed_objects == edge.traversed_objects
            ):
                return
        self.adjacency[edge.source].append(edge)

    def get_outgoing_edges(self, node: str) -> List[EscalationEdge]:
        return self.adjacency.get(node, [])


class GraphBuilder:
    """Constructs the escalation graph from an RBACCapabilityModel."""

    def __init__(self, model: RBACCapabilityModel) -> None:
        self.model = model

    def build_graph(self, excluded_remediations: Optional[Set[Tuple[str, str, int, str]]] = None) -> RBACGraph:
        """
        Builds and returns the escalation graph.
        excluded_remediations: optional set of (role_name, role_kind, rule_index, verb) or (binding_name, "BINDING", -1, "")
        used for virtual validation of remediations.
        """
        graph = RBACGraph()
        graph.add_node(ADMIN_TERMINAL)

        # Register all principals
        for p in self.model.all_principals:
            graph.add_node(p)

        # Find designated high-privilege / admin ClusterRoles
        admin_cluster_roles: Set[str] = set()
        for name, cr in self.model.cluster_roles.items():
            if self.model.is_admin_equivalent_role(cr):
                admin_cluster_roles.add(name)

        # Connect principals directly possessing cluster-wide admin capabilities
        for p in self.model.all_principals:
            if self.model.is_admin_equivalent(p):
                # Principal directly is admin
                pass  # We do not report escalation if already admin, but record node

        # For every principal, evaluate the 4 escalation primitives
        for p in self.model.all_principals:
            # If already admin, don't generate escalation edges from it
            if self.model.is_admin_equivalent(p):
                continue

            self._evaluate_binding_escalations(p, admin_cluster_roles, graph, excluded_remediations)
            self._evaluate_impersonations(p, graph, excluded_remediations)
            self._evaluate_pod_sa_escalations(p, graph, excluded_remediations)
            self._evaluate_credential_access(p, graph, excluded_remediations)

        return graph

    def _is_excluded(
        self,
        binding_name: str,
        role_name: str,
        role_kind: str,
        rule_idx: int,
        verb: str,
        excluded: Optional[Set[Tuple[str, str, int, str]]],
    ) -> bool:
        if not excluded:
            return False
        # Check binding-level exclusion
        if (binding_name, "BINDING", -1, "") in excluded:
            return True
        # Check verb-level exclusion
        if (role_name, role_kind, rule_idx, verb.lower()) in excluded:
            return True
        # Check wildcard verb exclusion
        if (role_name, role_kind, rule_idx, "*") in excluded:
            return True
        return False

    def _evaluate_binding_escalations(
        self,
        principal_id: str,
        admin_cluster_roles: Set[str],
        graph: RBACGraph,
        excluded: Optional[Set[Tuple[str, str, int, str]]],
    ) -> None:
        """
        Primitive 1: Binding escalation
        Principal can create/update RoleBinding/ClusterRoleBinding AND has bind verb
        on higher-privilege Role/ClusterRole.
        """
        rules = self.model.principal_scoped_rules.get(principal_id, [])

        # Check ClusterRoleBinding create/update permissions
        can_create_crb: List[ScopedRule] = []
        for sr in rules:
            if sr.namespace is None and sr.matches(verb="create", resource="clusterrolebindings", api_group="rbac.authorization.k8s.io"):
                can_create_crb.append(sr)
            elif sr.namespace is None and sr.matches(verb="update", resource="clusterrolebindings", api_group="rbac.authorization.k8s.io"):
                can_create_crb.append(sr)

        # Check RoleBinding create/update permissions per namespace
        can_create_rb_by_ns: Dict[str, List[ScopedRule]] = {}
        for sr in rules:
            for v in ("create", "update"):
                # Cluster-wide binding permission applies to all namespaces
                if sr.namespace is None and sr.matches(verb=v, resource="rolebindings", api_group="rbac.authorization.k8s.io"):
                    can_create_rb_by_ns.setdefault("*", []).append(sr)
                elif sr.namespace is not None and sr.matches(verb=v, resource="rolebindings", api_group="rbac.authorization.k8s.io", namespace=sr.namespace):
                    can_create_rb_by_ns.setdefault(sr.namespace, []).append(sr)

        # Check 'bind' permissions on ClusterRoles
        for cr_name, cr in self.model.cluster_roles.items():
            bind_rules = [
                sr for sr in rules
                if sr.matches(verb="bind", resource="clusterroles", api_group="rbac.authorization.k8s.io", resource_name=cr_name)
            ]
            if not bind_rules:
                continue

            is_admin_role = cr_name in admin_cluster_roles or self.model.is_admin_equivalent_role(cr)

            # Check if can bind via ClusterRoleBinding -> grants cluster-wide admin
            if can_create_crb and is_admin_role:
                for crb_sr in can_create_crb:
                    for b_sr in bind_rules:
                        # Check exclusions
                        if self._is_excluded(crb_sr.source_binding_name, crb_sr.source_role_name, crb_sr.source_role_kind, crb_sr.rule_index, "create", excluded):
                            continue
                        if self._is_excluded(b_sr.source_binding_name, b_sr.source_role_name, b_sr.source_role_kind, b_sr.rule_index, "bind", excluded):
                            continue

                        # Traversed YAML objects: binding granting create/bind, role(s), target cluster role
                        traversed = []
                        if crb_sr.source_binding_name:
                            traversed.append(crb_sr.source_binding_name)
                        if crb_sr.source_role_name and crb_sr.source_role_name not in traversed:
                            traversed.append(crb_sr.source_role_name)
                        if b_sr.source_binding_name and b_sr.source_binding_name not in traversed:
                            traversed.append(b_sr.source_binding_name)
                        if b_sr.source_role_name and b_sr.source_role_name not in traversed:
                            traversed.append(b_sr.source_role_name)
                        if cr_name not in traversed:
                            traversed.append(cr_name)

                        edge = EscalationEdge(
                            source=principal_id,
                            target=ADMIN_TERMINAL,
                            primitive=PRIMITIVE_BINDING_ESCALATION,
                            traversed_objects=tuple(traversed),
                            enabling_binding=b_sr.source_binding_name,
                            enabling_binding_kind=b_sr.source_binding_kind,
                            enabling_role=b_sr.source_role_name,
                            enabling_role_kind=b_sr.source_role_kind,
                            enabling_rule_index=b_sr.rule_index,
                            enabling_verb="bind",
                            remediation_candidate={
                                "type": "verb_removal",
                                "role_name": b_sr.source_role_name,
                                "role_kind": b_sr.source_role_kind,
                                "rule_index": b_sr.rule_index,
                                "verb": "bind",
                                "binding_name": b_sr.source_binding_name,
                            },
                        )
                        graph.add_edge(edge)

        # Check 'bind' permissions on namespaced Roles
        for (r_name, r_ns), role in self.model.roles.items():
            bind_rules = [
                sr for sr in rules
                if sr.matches(verb="bind", resource="roles", api_group="rbac.authorization.k8s.io", namespace=r_ns, resource_name=r_name)
            ]
            if not bind_rules:
                continue

            is_admin_role = self.model.is_admin_equivalent_role(role)
            rb_creators = can_create_rb_by_ns.get(r_ns, []) + can_create_rb_by_ns.get("*", [])

            if rb_creators and is_admin_role:
                for rb_sr in rb_creators:
                    for b_sr in bind_rules:
                        if self._is_excluded(rb_sr.source_binding_name, rb_sr.source_role_name, rb_sr.source_role_kind, rb_sr.rule_index, "create", excluded):
                            continue
                        if self._is_excluded(b_sr.source_binding_name, b_sr.source_role_name, b_sr.source_role_kind, b_sr.rule_index, "bind", excluded):
                            continue

                        traversed = []
                        if rb_sr.source_binding_name:
                            traversed.append(rb_sr.source_binding_name)
                        if rb_sr.source_role_name and rb_sr.source_role_name not in traversed:
                            traversed.append(rb_sr.source_role_name)
                        if b_sr.source_binding_name and b_sr.source_binding_name not in traversed:
                            traversed.append(b_sr.source_binding_name)
                        if b_sr.source_role_name and b_sr.source_role_name not in traversed:
                            traversed.append(b_sr.source_role_name)
                        if r_name not in traversed:
                            traversed.append(r_name)

                        edge = EscalationEdge(
                            source=principal_id,
                            target=ADMIN_TERMINAL,
                            primitive=PRIMITIVE_BINDING_ESCALATION,
                            traversed_objects=tuple(traversed),
                            enabling_binding=b_sr.source_binding_name,
                            enabling_binding_kind=b_sr.source_binding_kind,
                            enabling_role=b_sr.source_role_name,
                            enabling_role_kind=b_sr.source_role_kind,
                            enabling_rule_index=b_sr.rule_index,
                            enabling_verb="bind",
                            remediation_candidate={
                                "type": "verb_removal",
                                "role_name": b_sr.source_role_name,
                                "role_kind": b_sr.source_role_kind,
                                "rule_index": b_sr.rule_index,
                                "verb": "bind",
                                "binding_name": b_sr.source_binding_name,
                            },
                        )
                        graph.add_edge(edge)

    def _evaluate_impersonations(
        self,
        principal_id: str,
        graph: RBACGraph,
        excluded: Optional[Set[Tuple[str, str, int, str]]],
    ) -> None:
        """
        Primitive 2: Impersonation
        Principal has impersonate verb on users, groups, or serviceaccounts that
        have stronger permissions.
        """
        rules = self.model.principal_scoped_rules.get(principal_id, [])

        # Check for impersonation on users, groups, serviceaccounts
        for target_id in self.model.all_principals:
            if target_id == principal_id:
                continue

            # Target must be stronger than current principal
            if not self.model.is_stronger_principal(target_id, principal_id):
                continue

            # Determine resource kind to match
            if target_id.startswith("system:serviceaccount:"):
                parts = target_id.split(":")
                sa_name = parts[3] if len(parts) >= 4 else ""
                res_types = ["serviceaccounts"]
                res_name = sa_name
            elif target_id.startswith("User:"):
                res_types = ["users"]
                res_name = target_id[5:]
            elif target_id.startswith("Group:"):
                res_types = ["groups"]
                res_name = target_id[6:]
            else:
                res_types = ["users", "serviceaccounts"]
                res_name = target_id

            for res_type in res_types:
                matching = [
                    sr for sr in rules
                    if sr.matches(verb="impersonate", resource=res_type, api_group="", resource_name=res_name)
                    or sr.matches(verb="impersonate", resource=res_type, api_group="*", resource_name=res_name)
                ]
                for sr in matching:
                    if self._is_excluded(sr.source_binding_name, sr.source_role_name, sr.source_role_kind, sr.rule_index, "impersonate", excluded):
                        continue

                    traversed = []
                    if sr.source_binding_name:
                        traversed.append(sr.source_binding_name)
                    if sr.source_role_name and sr.source_role_name not in traversed:
                        traversed.append(sr.source_role_name)

                    # Include target object name if it exists in manifests
                    if target_id in self.model.service_accounts:
                        sa_obj = self.model.service_accounts[target_id]
                        if sa_obj.name not in traversed:
                            traversed.append(sa_obj.name)
                    elif res_name and res_name not in traversed:
                        traversed.append(res_name)

                    target_node = ADMIN_TERMINAL if self.model.is_admin_equivalent(target_id) else target_id

                    edge = EscalationEdge(
                        source=principal_id,
                        target=target_node,
                        primitive=PRIMITIVE_IMPERSONATION,
                        traversed_objects=tuple(traversed),
                        enabling_binding=sr.source_binding_name,
                        enabling_binding_kind=sr.source_binding_kind,
                        enabling_role=sr.source_role_name,
                        enabling_role_kind=sr.source_role_kind,
                        enabling_rule_index=sr.rule_index,
                        enabling_verb="impersonate",
                        remediation_candidate={
                            "type": "verb_removal",
                            "role_name": sr.source_role_name,
                            "role_kind": sr.source_role_kind,
                            "rule_index": sr.rule_index,
                            "verb": "impersonate",
                            "binding_name": sr.source_binding_name,
                        },
                    )
                    graph.add_edge(edge)

    def _evaluate_pod_sa_escalations(
        self,
        principal_id: str,
        graph: RBACGraph,
        excluded: Optional[Set[Tuple[str, str, int, str]]],
    ) -> None:
        """
        Primitive 3: Pod/service-account escalation
        Principal can create pods in a namespace where a stronger ServiceAccount exists.
        """
        rules = self.model.principal_scoped_rules.get(principal_id, [])

        # Find all namespaces where principal can create pods
        pod_create_rules_by_ns: Dict[str, List[ScopedRule]] = {}
        for sr in rules:
            if sr.matches(verb="create", resource="pods", api_group=""):
                if sr.namespace is None:
                    pod_create_rules_by_ns.setdefault("*", []).append(sr)
                else:
                    pod_create_rules_by_ns.setdefault(sr.namespace, []).append(sr)

        if not pod_create_rules_by_ns:
            return

        # Check every known ServiceAccount
        for sa_id, sa in self.model.service_accounts.items():
            if sa_id == principal_id:
                continue

            sa_ns = sa.namespace
            # Check if principal can create pods in sa_ns
            applicable_rules = pod_create_rules_by_ns.get(sa_ns, []) + pod_create_rules_by_ns.get("*", [])
            if not applicable_rules:
                continue

            # Must be stronger than principal
            if not self.model.is_stronger_principal(sa_id, principal_id):
                continue

            for sr in applicable_rules:
                if self._is_excluded(sr.source_binding_name, sr.source_role_name, sr.source_role_kind, sr.rule_index, "create", excluded):
                    continue

                traversed = []
                if sr.source_binding_name:
                    traversed.append(sr.source_binding_name)
                if sr.source_role_name and sr.source_role_name not in traversed:
                    traversed.append(sr.source_role_name)
                if sa.name not in traversed:
                    traversed.append(sa.name)

                target_node = ADMIN_TERMINAL if self.model.is_admin_equivalent(sa_id) else sa_id

                edge = EscalationEdge(
                    source=principal_id,
                    target=target_node,
                    primitive=PRIMITIVE_POD_SA_ESCALATION,
                    traversed_objects=tuple(traversed),
                    enabling_binding=sr.source_binding_name,
                    enabling_binding_kind=sr.source_binding_kind,
                    enabling_role=sr.source_role_name,
                    enabling_role_kind=sr.source_role_kind,
                    enabling_rule_index=sr.rule_index,
                    enabling_verb="create",
                    remediation_candidate={
                        "type": "verb_removal",
                        "role_name": sr.source_role_name,
                        "role_kind": sr.source_role_kind,
                        "rule_index": sr.rule_index,
                        "verb": "create",
                        "binding_name": sr.source_binding_name,
                    },
                )
                graph.add_edge(edge)

    def _evaluate_credential_access(
        self,
        principal_id: str,
        graph: RBACGraph,
        excluded: Optional[Set[Tuple[str, str, int, str]]],
    ) -> None:
        """
        Primitive 4: Service-account credential access
        Principal can get/list/watch a Secret that is a ServiceAccount token
        for a stronger ServiceAccount.
        """
        rules = self.model.principal_scoped_rules.get(principal_id, [])

        for sec in self.model.secrets:
            target_sa_id = sec.is_service_account_token_for()
            if not target_sa_id or target_sa_id == principal_id:
                continue

            # Target SA must be stronger than principal
            if not self.model.is_stronger_principal(target_sa_id, principal_id):
                continue

            # Check each rule for any secret read verbs: get, list, watch
            for sr in rules:
                matching_verbs = [
                    v for v in ("get", "list", "watch")
                    if sr.matches(verb=v, resource="secrets", api_group="", namespace=sec.namespace, resource_name=sec.name)
                ]
                if not matching_verbs:
                    continue

                active_verbs = [
                    v for v in matching_verbs
                    if not self._is_excluded(sr.source_binding_name, sr.source_role_name, sr.source_role_kind, sr.rule_index, v, excluded)
                ]
                if not active_verbs:
                    continue

                traversed = []
                if sr.source_binding_name:
                    traversed.append(sr.source_binding_name)
                if sr.source_role_name and sr.source_role_name not in traversed:
                    traversed.append(sr.source_role_name)
                if sec.name not in traversed:
                    traversed.append(sec.name)
                if sec.service_account_name and sec.service_account_name not in traversed:
                    traversed.append(sec.service_account_name)

                target_node = ADMIN_TERMINAL if self.model.is_admin_equivalent(target_sa_id) else target_sa_id

                edge = EscalationEdge(
                    source=principal_id,
                    target=target_node,
                    primitive=PRIMITIVE_CREDENTIAL_ACCESS,
                    traversed_objects=tuple(traversed),
                    enabling_binding=sr.source_binding_name,
                    enabling_binding_kind=sr.source_binding_kind,
                    enabling_role=sr.source_role_name,
                    enabling_role_kind=sr.source_role_kind,
                    enabling_rule_index=sr.rule_index,
                    enabling_verb=active_verbs[0],
                    enabling_verbs=tuple(active_verbs),
                    remediation_candidate={
                        "type": "verb_removal",
                        "role_name": sr.source_role_name,
                        "role_kind": sr.source_role_kind,
                        "rule_index": sr.rule_index,
                        "verb": active_verbs[0],
                        "verbs": tuple(active_verbs),
                        "binding_name": sr.source_binding_name,
                    },
                )
                graph.add_edge(edge)
