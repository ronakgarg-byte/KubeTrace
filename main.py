"""
main.py - Entry point for CY-05 Kubernetes RBAC Privilege Path Analyzer

Supports:
1. CLI execution: python main.py <manifests...> [-o report.json]
2. Cloud/Vercel Serverless Function: exports top-level `handler`, `app`, and `application`
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict

# Standard CLI orchestrator imports
from cli import main, build_capability_model
from graph_builder import GraphBuilder
from path_search import PathSearchEngine
from rbac_yaml_parser import RawRBACBundle, parse_yaml_content
from remediation import RemediationEngine
from report import ReportGenerator


class handler(BaseHTTPRequestHandler):
    """Vercel Serverless HTTP Handler for live web presentation and analysis."""

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Serve web dashboard at root
        if path in ("", "/", "/index.html"):
            root_dir = Path(__file__).resolve().parent
            dashboard_file = root_dir / "index.html"
            if not dashboard_file.exists():
                dashboard_file = root_dir / "web_dashboard.html"

            if dashboard_file.exists():
                content = dashboard_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        elif path == "/api/health":
            resp = json.dumps({"status": "ok", "service": "CY-05 RBAC Analyzer"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/analyze":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len)

            try:
                req_data = json.loads(post_body.decode("utf-8"))
                yaml_content = req_data.get("yaml", "")
                excluded = req_data.get("excluded_remediations", [])

                excluded_set = set()
                for item in excluded:
                    if len(item) == 4:
                        excluded_set.add((item[0], item[1], int(item[2]), str(item[3])))

                # Run offline static analysis in-memory
                bundle = RawRBACBundle()
                parse_yaml_content(yaml_content, bundle, origin_file="<live-editor>")
                model = build_capability_model(bundle)

                builder = GraphBuilder(model)
                graph = builder.build_graph(excluded_remediations=excluded_set if excluded_set else None)

                search_engine = PathSearchEngine(graph)
                paths_found = search_engine.find_all_escalation_paths()

                remediation_engine = RemediationEngine(model, builder)
                for p in paths_found:
                    p.remediation = remediation_engine.compute_minimal_remediation(p)

                report_dict = ReportGenerator.generate_report_dict(paths_found)

                # Format topology for interactive graph visualization
                graph_data = {"nodes": [], "edges": []}
                for node in graph.nodes:
                    if node == "CAPABILITY:ADMIN_EQUIVALENT":
                        graph_data["nodes"].append({"id": node, "label": "ADMIN EQUIVALENT (* on *)", "type": "admin"})
                    elif node.startswith("system:serviceaccount:"):
                        parts = node.split(":")
                        name = parts[3] if len(parts) >= 4 else node
                        ns = parts[2] if len(parts) >= 3 else "default"
                        graph_data["nodes"].append({"id": node, "label": f"{name} (SA: {ns})", "type": "serviceaccount"})
                    else:
                        graph_data["nodes"].append({"id": node, "label": node, "type": "principal"})

                for src, edge_list in graph.adjacency.items():
                    for e in edge_list:
                        graph_data["edges"].append({
                            "source": e.source,
                            "target": e.target,
                            "primitive": e.primitive,
                            "traversed": list(e.traversed_objects),
                            "enabling_role": e.enabling_role,
                            "enabling_verb": e.enabling_verb,
                        })

                resp = json.dumps({
                    "success": True,
                    "report": report_dict,
                    "graph": graph_data,
                }).encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

            except Exception as exc:
                err_resp = json.dumps({"success": False, "error": str(exc)}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(err_resp)))
                self.end_headers()
                self.wfile.write(err_resp)
            return

        self.send_response(404)
        self.end_headers()


# Vercel top-level variable exports
app = handler
application = handler


if __name__ == "__main__":
    sys.exit(main())
