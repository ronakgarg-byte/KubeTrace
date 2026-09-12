"""
web_server.py - Live Interactive Presentation Web Server for CY-05 Analyzer

Provides a local web server and REST API for real-time demonstration to evaluators:
- Serves an interactive visualization dashboard
- In-memory YAML manifest analysis in milliseconds
- Live remediation verification toggles
- Built-in dev bundles and custom YAML uploads
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import urllib.parse
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List

# Ensure local imports work
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from cli import analyze_manifests, build_capability_model
from graph_builder import GraphBuilder
from path_search import PathSearchEngine
from rbac_yaml_parser import RawRBACBundle, parse_manifests, parse_yaml_content
from remediation import RemediationEngine
from report import ReportGenerator


BUNDLES_DIR = PROJECT_ROOT / "tests" / "dev_bundles"


class AnalyzerHTTPHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler serving dashboard and analysis endpoints."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(PROJECT_ROOT), **kwargs)

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/" or path == "/index.html":
            dashboard_path = PROJECT_ROOT / "web_dashboard.html"
            if dashboard_path.exists():
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(dashboard_path, "rb") as f:
                    self.wfile.write(f.read())
                return

        elif path == "/api/bundles":
            self._handle_list_bundles()
            return

        super().do_GET()

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/analyze":
            self._handle_analyze()
            return

        self.send_error(404, "Endpoint not found")

    def _send_json(self, data: Any, status: int = 200) -> None:
        content = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _handle_list_bundles(self) -> None:
        bundles = {}
        if BUNDLES_DIR.exists():
            for f in sorted(BUNDLES_DIR.glob("*.yaml")):
                with open(f, "r", encoding="utf-8") as bf:
                    bundles[f.name] = bf.read()
        self._send_json({"bundles": bundles})

    def _handle_analyze(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len)

        try:
            req_data = json.loads(post_body.decode("utf-8"))
            yaml_content = req_data.get("yaml", "")
            excluded = req_data.get("excluded_remediations", [])  # list of [role, kind, idx, verb]

            excluded_set = set()
            for item in excluded:
                if len(item) == 4:
                    excluded_set.add((item[0], item[1], int(item[2]), str(item[3])))

            # Parse YAML in memory
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

            # Build visual nodes and edges for the graph renderer
            graph_data = {
                "nodes": [],
                "edges": [],
            }

            # Map nodes
            for node in graph.nodes:
                if node == "CAPABILITY:ADMIN_EQUIVALENT":
                    graph_data["nodes"].append({
                        "id": node,
                        "label": "ADMIN EQUIVALENT (* on *)",
                        "type": "admin",
                    })
                elif node.startswith("system:serviceaccount:"):
                    parts = node.split(":")
                    name = parts[3] if len(parts) >= 4 else node
                    ns = parts[2] if len(parts) >= 3 else "default"
                    graph_data["nodes"].append({
                        "id": node,
                        "label": f"{name} (SA: {ns})",
                        "type": "serviceaccount",
                    })
                else:
                    graph_data["nodes"].append({
                        "id": node,
                        "label": node,
                        "type": "principal",
                    })

            # Map edges
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

            self._send_json({
                "success": True,
                "report": report_dict,
                "graph": graph_data,
                "summary": {
                    "total_roles": len(model.roles) + len(model.cluster_roles),
                    "total_bindings": len(model.role_bindings) + len(model.cluster_role_bindings),
                    "total_principals": len(model.all_principals),
                    "total_secrets": len(model.secrets),
                }
            })

        except Exception as exc:
            self._send_json({"success": False, "error": str(exc)}, status=400)


def start_server(port: int = 8080) -> None:
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, AnalyzerHTTPHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n========================================================")
    print(f"  CY-05 KUBERNETES RBAC ANALYZER - LIVE PRESENTATION UI")
    print(f"========================================================")
    print(f"[+] Server running at: {url}")
    print(f"[+] Press Ctrl+C to stop the server")
    print(f"========================================================\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Server stopped.")


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    start_server(port)
