"""
test_analyzer.py - Comprehensive Unit and Integration Test Suite

Verifies:
1. Benign configurations produce zero escalation paths (100% precision)
2. Each of the four escalation primitives is correctly detected with exact names
3. ClusterRole aggregation resolution works
4. Scoped RoleBindings over ClusterRoles do not leak cluster-wide
5. Cycles (e.g. mutual impersonation) do not cause infinite loops
6. Reflexive/already-privileged paths are suppressed
7. Every minimal remediation is validated and breaks the corresponding path
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cli import analyze_manifests
from graph_builder import (
    PRIMITIVE_BINDING_ESCALATION,
    PRIMITIVE_CREDENTIAL_ACCESS,
    PRIMITIVE_IMPERSONATION,
    PRIMITIVE_POD_SA_ESCALATION,
)
from rbac_yaml_parser import parse_manifests


class TestRBACAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.bundles_dir = PROJECT_ROOT / "tests" / "dev_bundles"

    def test_benign_01(self) -> None:
        """Benign bundle 1 should produce zero escalation paths."""
        bundle_file = self.bundles_dir / "benign_01.yaml"
        paths = analyze_manifests([bundle_file])
        self.assertEqual(len(paths), 0, f"Expected 0 paths in benign_01, found {len(paths)}")

    def test_benign_02_aggregated_and_scoped(self) -> None:
        """Benign bundle 2 with aggregated ClusterRole scoped in RoleBinding produces zero paths."""
        bundle_file = self.bundles_dir / "benign_02.yaml"
        paths = analyze_manifests([bundle_file])
        self.assertEqual(len(paths), 0, f"Expected 0 paths in benign_02, found {len(paths)}")

    def test_escalation_binding(self) -> None:
        """Isolated binding escalation detection and minimal remediation."""
        bundle_file = self.bundles_dir / "escalation_binding.yaml"
        paths = analyze_manifests([bundle_file])
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p.source_principal, "system:serviceaccount:default:sa0")
        self.assertEqual(p.escalation_primitive, PRIMITIVE_BINDING_ESCALATION)
        self.assertIn("r9", p.traversed_objects)
        self.assertIn("bind0", p.traversed_objects)
        self.assertIsNotNone(p.remediation)
        self.assertTrue(p.remediation.get("validated"))
        self.assertEqual(p.remediation.get("action"), "remove_verb")
        self.assertEqual(p.remediation.get("verb"), "bind")

    def test_escalation_impersonation(self) -> None:
        """Isolated impersonation detection and minimal remediation."""
        bundle_file = self.bundles_dir / "escalation_impersonation.yaml"
        paths = analyze_manifests([bundle_file])
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p.source_principal, "system:serviceaccount:default:sa1")
        self.assertEqual(p.escalation_primitive, PRIMITIVE_IMPERSONATION)
        self.assertIn("sa7", p.traversed_objects)
        self.assertIsNotNone(p.remediation)
        self.assertTrue(p.remediation.get("validated"))
        self.assertEqual(p.remediation.get("action"), "remove_verb")
        self.assertEqual(p.remediation.get("verb"), "impersonate")

    def test_escalation_pod_sa(self) -> None:
        """Isolated pod/service-account escalation detection and minimal remediation."""
        bundle_file = self.bundles_dir / "escalation_pod_sa.yaml"
        paths = analyze_manifests([bundle_file])
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p.source_principal, "system:serviceaccount:prod:sa2")
        self.assertEqual(p.escalation_primitive, PRIMITIVE_POD_SA_ESCALATION)
        self.assertIn("sa7", p.traversed_objects)
        self.assertIsNotNone(p.remediation)
        self.assertTrue(p.remediation.get("validated"))
        self.assertEqual(p.remediation.get("action"), "remove_verb")
        self.assertEqual(p.remediation.get("verb"), "create")

    def test_escalation_credential_access(self) -> None:
        """Isolated secret credential access detection and minimal remediation."""
        bundle_file = self.bundles_dir / "escalation_credential_access.yaml"
        paths = analyze_manifests([bundle_file])
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p.source_principal, "system:serviceaccount:kube-system:sa3")
        self.assertEqual(p.escalation_primitive, PRIMITIVE_CREDENTIAL_ACCESS)
        self.assertIn("sa7-token", p.traversed_objects)
        self.assertIsNotNone(p.remediation)
        self.assertTrue(p.remediation.get("validated"))
        self.assertTrue(any(v in p.remediation.get("verb", "") for v in ["get", "list", "watch"]))

    def test_combined_bundle_all_primitives_and_cycles(self) -> None:
        """Combined bundle tests all four primitives, cycle handling, and benign exclusion."""
        bundle_file = self.bundles_dir / "escalation_combined.yaml"
        paths = analyze_manifests([bundle_file])

        # Expect exactly 4 paths for sa0, sa1, sa2, sa3
        source_principals = [p.source_principal for p in paths]
        self.assertEqual(len(paths), 4, f"Expected 4 paths, got: {source_principals}")

        primitives_found = {p.source_principal: p.escalation_primitive for p in paths}
        self.assertEqual(primitives_found["system:serviceaccount:default:sa0"], PRIMITIVE_BINDING_ESCALATION)
        self.assertEqual(primitives_found["system:serviceaccount:default:sa1"], PRIMITIVE_IMPERSONATION)
        self.assertEqual(primitives_found["system:serviceaccount:default:sa2"], PRIMITIVE_POD_SA_ESCALATION)
        self.assertEqual(primitives_found["system:serviceaccount:default:sa3"], PRIMITIVE_CREDENTIAL_ACCESS)

        # Confirm sa6 (benign) has no path
        self.assertNotIn("system:serviceaccount:default:sa6", source_principals)

        # Confirm sa4 and sa5 (cycle) have no path to admin
        self.assertNotIn("system:serviceaccount:default:sa4", source_principals)
        self.assertNotIn("system:serviceaccount:default:sa5", source_principals)

        # Confirm sa7 (already admin) has no reflexive path
        self.assertNotIn("system:serviceaccount:default:sa7", source_principals)

        # Confirm all remediations are validated
        for p in paths:
            self.assertTrue(p.remediation.get("validated"), f"Remediation not validated for {p.source_principal}")

    def test_namespace_isolation(self) -> None:
        """RoleBinding in ns-a referencing ClusterRole with pods create does NOT leak to ns-b."""
        from capability_model import PolicyRule, RoleObject, BindingObject, Principal, RBACCapabilityModel
        from graph_builder import GraphBuilder
        from path_search import PathSearchEngine

        model = RBACCapabilityModel()
        # ClusterRole granting pod creation
        model.add_role(RoleObject(
            name="pod-creator",
            namespace=None,
            is_cluster_role=True,
            rules=[PolicyRule(api_groups=("",), resources=("pods",), verbs=("create",))]
        ))
        # Admin SA in ns-b
        from capability_model import ServiceAccountObject
        model.add_service_account(ServiceAccountObject(name="admin-sa", namespace="ns-b"))
        # Admin Role in ns-b
        model.add_role(RoleObject(
            name="admin-role",
            namespace=None,
            is_cluster_role=True,
            rules=[PolicyRule(api_groups=("*",), resources=("*",), verbs=("*",))]
        ))
        model.add_binding(BindingObject(
            name="admin-bind",
            namespace="ns-b",
            is_cluster_binding=False,
            role_ref_kind="ClusterRole",
            role_ref_name="admin-role",
            role_ref_api_group="rbac.authorization.k8s.io",
            subjects=[Principal(kind="ServiceAccount", name="admin-sa", namespace="ns-b")]
        ))
        # Attacker SA in ns-a bound to pod-creator via RoleBinding in ns-a
        model.add_service_account(ServiceAccountObject(name="attacker-sa", namespace="ns-a"))
        model.add_binding(BindingObject(
            name="attacker-bind",
            namespace="ns-a",
            is_cluster_binding=False,
            role_ref_kind="ClusterRole",
            role_ref_name="pod-creator",
            role_ref_api_group="rbac.authorization.k8s.io",
            subjects=[Principal(kind="ServiceAccount", name="attacker-sa", namespace="ns-a")]
        ))
        model.bind_rules_to_principals()

        graph = GraphBuilder(model).build_graph()
        paths = PathSearchEngine(graph).find_all_escalation_paths()
        # Since attacker cannot create pods in ns-b, attacker CANNOT escalate to admin-sa in ns-b
        self.assertEqual(len(paths), 0, "Attacker should not escalate across isolated namespaces!")

    def test_wildcard_expansion(self) -> None:
        """Verifies wildcard matching on apiGroups, resources, verbs, and subresources."""
        from capability_model import PolicyRule
        rule = PolicyRule(api_groups=("*",), resources=("pods/*",), verbs=("*",))
        self.assertTrue(rule.allows_verb("create"))
        self.assertTrue(rule.allows_verb("delete"))
        self.assertTrue(rule.allows_api_group("custom.k8s.io"))
        self.assertTrue(rule.allows_resource("pods/exec"))
        self.assertTrue(rule.allows_resource("pods/attach"))
        self.assertFalse(rule.allows_resource("services"))

    def test_cli_execution(self) -> None:
        """Verifies CLI execution with JSON and text output options."""
        from cli import main
        import tempfile
        bundle_file = str(self.bundles_dir / "escalation_binding.yaml")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            exit_code = main([bundle_file, "-o", tmp_path, "--quiet"])
            self.assertEqual(exit_code, 0)
            self.assertTrue(Path(tmp_path).exists())
            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Binding escalation", content)
            self.assertIn("source_principal", content)
            self.assertIn("remediation", content)
        finally:
            if Path(tmp_path).exists():
                Path(tmp_path).unlink()


if __name__ == "__main__":
    unittest.main()

