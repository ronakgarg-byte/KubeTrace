"""
cli.py - Command-Line Interface and Pipeline Orchestrator

Ingests Kubernetes manifests, coordinates parsing, capability modeling, graph construction,
path discovery, minimal remediation validation, and report emission.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from capability_model import (
    BindingObject,
    RBACCapabilityModel,
    RoleObject,
    SecretObject,
    ServiceAccountObject,
)
from graph_builder import GraphBuilder
from path_search import PathSearchEngine, PrivilegePath
from rbac_yaml_parser import RawRBACBundle, parse_manifests
from remediation import RemediationEngine
from report import ReportGenerator


def build_capability_model(raw_bundle: RawRBACBundle) -> RBACCapabilityModel:
    """Instantiates and populates the capability model from a raw bundle."""
    model = RBACCapabilityModel()

    # Load Roles
    for r in raw_bundle.roles:
        model.add_role(RoleObject.from_dict(r, is_cluster_role=False))

    # Load ClusterRoles
    for cr in raw_bundle.cluster_roles:
        model.add_role(RoleObject.from_dict(cr, is_cluster_role=True))

    # Load RoleBindings
    for rb in raw_bundle.role_bindings:
        model.add_binding(BindingObject.from_dict(rb, is_cluster_binding=False))

    # Load ClusterRoleBindings
    for crb in raw_bundle.cluster_role_bindings:
        model.add_binding(BindingObject.from_dict(crb, is_cluster_binding=True))

    # Load ServiceAccounts
    for sa in raw_bundle.service_accounts:
        model.add_service_account(ServiceAccountObject.from_dict(sa))

    # Load Secrets
    for sec in raw_bundle.secrets:
        model.add_secret(SecretObject.from_dict(sec))

    # Resolve aggregations and bind rules
    model.resolve_cluster_role_aggregations()
    model.bind_rules_to_principals()

    return model


def analyze_manifests(paths: List[str | Path]) -> List[PrivilegePath]:
    """
    Executes the full static analysis pipeline across the provided manifest paths:
    parse -> model -> graph -> search -> remediate.
    """
    raw_bundle = parse_manifests(paths)
    model = build_capability_model(raw_bundle)

    builder = GraphBuilder(model)
    graph = builder.build_graph()

    search_engine = PathSearchEngine(graph)
    paths_found = search_engine.find_all_escalation_paths()

    # Compute minimal remediations
    remediation_engine = RemediationEngine(model, builder)
    for p in paths_found:
        p.remediation = remediation_engine.compute_minimal_remediation(p)

    return paths_found


def main(args: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="CY-05 Kubernetes RBAC Privilege Path Analyzer (Offline Static Security Analyzer)"
    )
    parser.add_argument(
        "manifests",
        nargs="+",
        help="One or more YAML manifest files or directories containing manifests",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to save the JSON analysis report",
        default=None,
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Console output format (default: json)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-essential console output",
    )

    parsed_args = parser.parse_args(args)

    try:
        paths_found = analyze_manifests(parsed_args.manifests)

        if parsed_args.output:
            ReportGenerator.write_json_report(paths_found, parsed_args.output)
            if not parsed_args.quiet:
                print(f"[+] Wrote analysis report with {len(paths_found)} paths to {parsed_args.output}")

        if not parsed_args.quiet or not parsed_args.output:
            if parsed_args.format == "text":
                ReportGenerator.print_text_summary(paths_found)
            else:
                import json
                print(json.dumps(ReportGenerator.generate_report_dict(paths_found), indent=2))

        return 0

    except Exception as exc:
        print(f"[-] Error during analysis: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
