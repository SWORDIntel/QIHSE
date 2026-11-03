import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.qihse_deps import topological_order, validate_manifest


class DependencyManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "src/example.c").write_text("evidence", encoding="utf-8")
        self.path = self.root / "deps.json"
        self.data = {
            "schema_version": 1,
            "repository": "test-repo",
            "items": [
                {"id": "child", "title": "Child", "status": "planned",
                 "description": "child item", "depends_on": ["base"],
                 "evidence": ["src/example.c"], "acceptance": ["works"]},
                {"id": "base", "title": "Base", "status": "complete",
                 "description": "base item", "depends_on": [],
                 "evidence": [], "acceptance": ["works"]},
            ],
        }

    def tearDown(self):
        self.temp.cleanup()

    def errors(self):
        return validate_manifest(self.data, self.path)

    def test_valid_graph_orders_prerequisites_first(self):
        self.assertEqual(self.errors(), [])
        graph = {item["id"]: item["depends_on"] for item in self.data["items"]}
        self.assertEqual(topological_order(graph), ["base", "child"])

    def test_duplicate_ids_fail(self):
        self.data["items"].append(dict(self.data["items"][0]))
        self.assertTrue(any("duplicate item id" in error for error in self.errors()))

    def test_unknown_dependency_fails(self):
        self.data["items"][0]["depends_on"] = ["missing"]
        self.assertTrue(any("unknown dependency" in error for error in self.errors()))

    def test_cycle_fails(self):
        self.data["items"][1]["depends_on"] = ["child"]
        self.assertTrue(any("cycle" in error for error in self.errors()))

    def test_self_and_duplicate_dependencies_fail(self):
        self.data["items"][1]["depends_on"] = ["base", "base"]
        errors = self.errors()
        self.assertTrue(any("contains duplicates" in error for error in errors))
        self.assertTrue(any("depends on itself" in error for error in errors))

    def test_malformed_dependency_and_status_types_fail_cleanly(self):
        self.data["items"][0]["depends_on"] = [["not", "an", "id"]]
        self.data["items"][0]["status"] = ["planned"]
        self.assertTrue(self.errors())

    def test_invalid_status_fails(self):
        self.data["items"][0]["status"] = "done-ish"
        self.assertTrue(any("status" in error for error in self.errors()))

    def test_missing_evidence_fails(self):
        self.data["items"][0]["evidence"] = ["missing.txt"]
        self.assertTrue(any("does not exist" in error for error in self.errors()))

    def test_evidence_cannot_escape_repository(self):
        self.data["items"][0]["evidence"] = ["../../etc/passwd"]
        self.assertTrue(any("stay inside" in error for error in self.errors()))

    def test_cli_uses_selected_manifest(self):
        self.path.write_text(json.dumps(self.data), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/qihse_deps.py"),
             "--manifest", str(self.path), "order"],
            cwd=self.root, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["base", "child"])

    def test_cli_default_manifest_is_repo_local(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/qihse_deps.py"), "validate"],
            cwd=self.root, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("5 items", result.stdout)


if __name__ == "__main__":
    unittest.main()
