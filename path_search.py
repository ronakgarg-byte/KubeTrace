"""
path_search.py - Cycle-Safe Privilege Path Search Engine

Traverses the RBAC capability and escalation graph using Breadth-First Search (BFS)
to discover shortest privilege paths from non-administrator principals to
administrator-equivalent capabilities.
Features:
- Cycle-safe path-history tracking
- Optimal shortest-path discovery per (source_principal, escalation_primitive)
- Prunes redundant detours and reflexive/already-privileged paths
- Ordered YAML object traversal recording
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from graph_builder import (
    ADMIN_TERMINAL,
    EscalationEdge,
    RBACGraph,
)


@dataclass
class PrivilegePath:
    """Represents a complete privilege escalation path from a source principal to admin."""
    source_principal: str
    target_principal: str
    escalation_primitive: str
    traversed_objects: List[str]
    terminal_capability: str
    edges: List[EscalationEdge] = field(default_factory=list)
    remediation: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_principal": self.source_principal,
            "escalation_primitive": self.escalation_primitive,
            "traversed_objects": list(self.traversed_objects),
            "terminal_capability": self.terminal_capability,
            "remediation": self.remediation,
        }


class PathSearchEngine:
    """Search engine to find privilege escalation paths in an RBACGraph."""

    def __init__(self, graph: RBACGraph) -> None:
        self.graph = graph

    def find_all_escalation_paths(self) -> List[PrivilegePath]:
        """
        Searches the graph for all non-reflexive shortest paths from non-admin principals
        to the terminal admin capability.
        """
        all_paths: List[PrivilegePath] = []
        seen_signatures: Set[Tuple[str, str]] = set()

        for node in sorted(self.graph.nodes):
            if node == ADMIN_TERMINAL:
                continue

            paths_from_source = self._search_paths_from_source(node)
            for path in paths_from_source:
                sig = (path.source_principal, path.escalation_primitive)
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)
                all_paths.append(path)

        return all_paths

    def _search_paths_from_source(self, source_principal: str) -> List[PrivilegePath]:
        """
        Uses Breadth-First Search (BFS) to find the shortest acyclic privilege paths
        from source_principal to ADMIN_TERMINAL.
        """
        results: List[PrivilegePath] = []
        queue: deque[Tuple[str, List[EscalationEdge], Set[str]]] = deque([
            (source_principal, [], {source_principal})
        ])

        found_primitives_for_source: Set[str] = set()

        while queue:
            curr_node, edge_history, visited = queue.popleft()

            outgoing = self.graph.get_outgoing_edges(curr_node)
            for edge in outgoing:
                next_node = edge.target

                if next_node == ADMIN_TERMINAL:
                    full_edges = edge_history + [edge]
                    primary_primitive = full_edges[0].primitive

                    if primary_primitive in found_primitives_for_source:
                        continue
                    found_primitives_for_source.add(primary_primitive)

                    # Aggregate traversed YAML objects in order
                    traversed: List[str] = []
                    for e in full_edges:
                        for obj in e.traversed_objects:
                            if not traversed or traversed[-1] != obj:
                                traversed.append(obj)

                    path = PrivilegePath(
                        source_principal=source_principal,
                        target_principal=ADMIN_TERMINAL,
                        escalation_primitive=primary_primitive,
                        traversed_objects=traversed,
                        terminal_capability="administrator-equivalent: verbs: ['*'], resources: ['*']",
                        edges=full_edges,
                    )
                    results.append(path)

                elif next_node not in visited:
                    new_visited = visited | {next_node}
                    queue.append((next_node, edge_history + [edge], new_visited))

        return results
