"""
rbac_yaml_parser.py - Kubernetes RBAC YAML Parser

Loads and parses Kubernetes manifests from files or directories, extracting
Role, ClusterRole, RoleBinding, ClusterRoleBinding, ServiceAccount, and Secret
objects into structured representations.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


class RawRBACBundle:
    """Container for raw Kubernetes objects parsed from manifests."""

    def __init__(self) -> None:
        self.roles: List[Dict[str, Any]] = []
        self.cluster_roles: List[Dict[str, Any]] = []
        self.role_bindings: List[Dict[str, Any]] = []
        self.cluster_role_bindings: List[Dict[str, Any]] = []
        self.service_accounts: List[Dict[str, Any]] = []
        self.secrets: List[Dict[str, Any]] = []
        self.raw_documents: List[Dict[str, Any]] = []

    def extend(self, other: RawRBACBundle) -> None:
        self.roles.extend(other.roles)
        self.cluster_roles.extend(other.cluster_roles)
        self.role_bindings.extend(other.role_bindings)
        self.cluster_role_bindings.extend(other.cluster_role_bindings)
        self.service_accounts.extend(other.service_accounts)
        self.secrets.extend(other.secrets)
        self.raw_documents.extend(other.raw_documents)


def parse_yaml_document(doc: Dict[str, Any], bundle: RawRBACBundle, origin_file: Optional[str] = None) -> None:
    """Parses a single Kubernetes YAML document dict and categorizes it."""
    if not isinstance(doc, dict):
        return

    kind = doc.get("kind")
    if not kind or not isinstance(kind, str):
        return

    metadata = doc.get("metadata") or {}
    if not isinstance(metadata, dict):
        return

    name = metadata.get("name")
    if not name:
        return

    doc_copy = dict(doc)
    doc_copy["_origin_file"] = origin_file
    bundle.raw_documents.append(doc_copy)

    kind_upper = kind.strip().upper()
    if kind_upper == "ROLE":
        bundle.roles.append(doc_copy)
    elif kind_upper == "CLUSTERROLE":
        bundle.cluster_roles.append(doc_copy)
    elif kind_upper == "ROLEBINDING":
        bundle.role_bindings.append(doc_copy)
    elif kind_upper == "CLUSTERROLEBINDING":
        bundle.cluster_role_bindings.append(doc_copy)
    elif kind_upper == "SERVICEACCOUNT":
        bundle.service_accounts.append(doc_copy)
    elif kind_upper == "SECRET":
        bundle.secrets.append(doc_copy)


def parse_yaml_content(content: str, bundle: RawRBACBundle, origin_file: Optional[str] = None) -> None:
    """Parses a multi-document YAML string."""
    try:
        docs = yaml.safe_load_all(content)
        for doc in docs:
            if doc and isinstance(doc, dict):
                parse_yaml_document(doc, bundle, origin_file=origin_file)
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML parsing error in {origin_file or '<string>'}: {exc}") from exc


def parse_yaml_file(file_path: str | Path, bundle: RawRBACBundle) -> None:
    """Reads and parses a single YAML file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    parse_yaml_content(content, bundle, origin_file=str(path))


def parse_manifests(paths: List[str | Path]) -> RawRBACBundle:
    """
    Parses one or more file or directory paths.
    Traverses directories recursively for .yaml and .yml files.
    """
    bundle = RawRBACBundle()
    for p in paths:
        path = Path(p)
        if not path.exists():
            raise FileNotFoundError(f"Manifest path does not exist: {p}")

        if path.is_dir():
            for root, _, files in os.walk(path):
                for file in sorted(files):
                    if file.lower().endswith((".yaml", ".yml")):
                        file_path = Path(root) / file
                        parse_yaml_file(file_path, bundle)
        else:
            parse_yaml_file(path, bundle)

    return bundle
