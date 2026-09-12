"""
remediation.py - Minimal Remediation Engine

Generates and validates minimal remediations for discovered privilege escalation paths.
A minimal remediation targets the smallest possible edge (preferring a single verb
in a specific rule over an entire rule or binding) whose removal breaks the path.
Validates candidate remediations by virtually re-evaluating the graph and path search.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from capability_model import RBACCapabilityModel
from graph_builder import GraphBuilder
from path_search import PathSearchEngine, PrivilegePath


class RemediationEngine:
    """Computes and validates minimal remediations for privilege escalation paths."""

    def __init__(self, model: RBACCapabilityModel, builder: GraphBuilder) -> None:
        self.model = model
        self.builder = builder

    def compute_minimal_remediation(self, path: PrivilegePath) -> Dict[str, Any]:
        """
        Calculates and validates the single minimal permission removal that breaks
        the given escalation path.
        """
        candidates: List[Dict[str, Any]] = []

        for edge in path.edges:
            # Candidate 1: Remove specific verb from the enabling role's rule
            if edge.enabling_role and edge.enabling_verb and edge.enabling_rule_index is not None:
                candidates.append({
                    "action": "remove_verb",
                    "target_kind": edge.enabling_role_kind or "Role",
                    "target_name": edge.enabling_role,
                    "rule_index": edge.enabling_rule_index,
                    "verb": edge.enabling_verb,
                    "description": (
                        f"Remove verb '{edge.enabling_verb}' from rule #{edge.enabling_rule_index} "
                        f"in {edge.enabling_role_kind or 'Role'} '{edge.enabling_role}'"
                    ),
                    "exclusions": [
                        (
                            edge.enabling_role,
                            edge.enabling_role_kind or "Role",
                            edge.enabling_rule_index,
                            edge.enabling_verb.lower(),
                        )
                    ],
                })

            # Candidate 2: If multiple verbs enabled this primitive in the same rule, remove all of them
            if edge.enabling_role and len(edge.enabling_verbs) > 1 and edge.enabling_rule_index is not None:
                verbs_str = ", ".join(f"'{v}'" for v in edge.enabling_verbs)
                candidates.append({
                    "action": "remove_verb",
                    "target_kind": edge.enabling_role_kind or "Role",
                    "target_name": edge.enabling_role,
                    "rule_index": edge.enabling_rule_index,
                    "verb": ", ".join(edge.enabling_verbs),
                    "description": (
                        f"Remove verbs {verbs_str} from rule #{edge.enabling_rule_index} "
                        f"in {edge.enabling_role_kind or 'Role'} '{edge.enabling_role}'"
                    ),
                    "exclusions": [
                        (
                            edge.enabling_role,
                            edge.enabling_role_kind or "Role",
                            edge.enabling_rule_index,
                            v.lower(),
                        )
                        for v in edge.enabling_verbs
                    ],
                })

            # Candidate 3: Remove the binding
            if edge.enabling_binding:
                candidates.append({
                    "action": "remove_binding",
                    "target_kind": edge.enabling_binding_kind or "RoleBinding",
                    "target_name": edge.enabling_binding,
                    "description": f"Remove {edge.enabling_binding_kind or 'RoleBinding'} '{edge.enabling_binding}'",
                    "exclusions": [(edge.enabling_binding, "BINDING", -1, "")],
                })

        # Test each candidate by virtual removal to confirm it breaks the path
        for cand in candidates:
            exclusions = cand["exclusions"]
            if self._validate_remediation(path, exclusions):
                res = {
                    "action": cand["action"],
                    "target_kind": cand["target_kind"],
                    "target_name": cand["target_name"],
                    "description": cand["description"],
                    "validated": True,
                }
                if cand["action"] == "remove_verb":
                    res["rule_index"] = cand["rule_index"]
                    res["verb"] = cand["verb"]
                return res

        # Fallback if virtual check somehow didn't catch (e.g. edge case)
        if candidates:
            cand = candidates[0]
            res = {
                "action": cand["action"],
                "target_kind": cand["target_kind"],
                "target_name": cand["target_name"],
                "description": cand["description"],
                "validated": False,
            }
            if cand["action"] == "remove_verb":
                res["rule_index"] = cand["rule_index"]
                res["verb"] = cand["verb"]
            return res

        return {
            "action": "manual_review",
            "description": "Review permissions for source principal",
            "validated": False,
        }

    def _validate_remediation(
        self,
        path: PrivilegePath,
        exclusions: List[Tuple[str, str, int, str]],
    ) -> bool:
        """
        Re-builds the graph virtually with the candidate excluded and verifies
        that the original path no longer exists.
        """
        virtual_graph = self.builder.build_graph(excluded_remediations=set(exclusions))
        virtual_search = PathSearchEngine(virtual_graph)
        virtual_paths = virtual_search._search_paths_from_source(path.source_principal)

        # Check if the exact path (or equivalent primitive traversal) is gone
        path_traversed_tuple = tuple(path.traversed_objects)
        for vp in virtual_paths:
            if (
                vp.source_principal == path.source_principal
                and vp.escalation_primitive == path.escalation_primitive
                and tuple(vp.traversed_objects) == path_traversed_tuple
            ):
                return False  # Path still exists!

        return True  # Path successfully broken!
