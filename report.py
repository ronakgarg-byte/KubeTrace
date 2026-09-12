"""
report.py - JSON Path and Remediation Report Formatter

Serializes discovered privilege escalation paths into the standardized machine-readable
JSON schema satisfying all explanation completeness criteria.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from path_search import PrivilegePath


class ReportGenerator:
    """Generates machine-readable JSON reports from path search results."""

    @staticmethod
    def generate_report_dict(paths: List[PrivilegePath]) -> Dict[str, Any]:
        """
        Creates a dictionary adhering strictly to the explanation completeness
        specifications:
        - source principal
        - ordered list of YAML object names traversed
        - in-scope escalation primitive used
        - terminal admin-equivalent capability
        - suggested minimal remediation
        """
        path_records = []
        for p in paths:
            record = {
                "source_principal": p.source_principal,
                "traversed_objects": p.traversed_objects,
                "escalation_primitive": p.escalation_primitive,
                "terminal_capability": p.terminal_capability,
                "remediation": p.remediation or {},
            }
            path_records.append(record)

        # Count primitives breakdown
        primitive_counts: Dict[str, int] = {}
        for p in paths:
            primitive_counts[p.escalation_primitive] = primitive_counts.get(p.escalation_primitive, 0) + 1

        return {
            "summary": {
                "total_paths_detected": len(paths),
                "unique_source_principals": len(set(p.source_principal for p in paths)),
                "primitive_breakdown": primitive_counts,
            },
            "paths": path_records,
        }

    @classmethod
    def write_json_report(cls, paths: List[PrivilegePath], output_path: str | Path) -> str:
        """Writes the report JSON to the specified file path."""
        report_data = cls.generate_report_dict(paths)
        json_content = json.dumps(report_data, indent=2)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(json_content)
        return json_content

    @classmethod
    def print_text_summary(cls, paths: List[PrivilegePath]) -> None:
        """Prints a human-readable summary of the detected paths."""
        print(f"\n==================================================")
        print(f"  CY-05 KUBERNETES RBAC PRIVILEGE PATH ANALYZER")
        print(f"==================================================")
        print(f"Total escalation paths detected: {len(paths)}\n")

        for idx, p in enumerate(paths, 1):
            print(f"Path #{idx}:")
            print(f"  Source Principal   : {p.source_principal}")
            print(f"  Escalation Type    : {p.escalation_primitive}")
            print(f"  Traversed YAML     : {' -> '.join(p.traversed_objects)}")
            print(f"  Terminal Capability: {p.terminal_capability}")
            if p.remediation:
                print(f"  Minimal Remediation: {p.remediation.get('description')}")
            print("-" * 50)
