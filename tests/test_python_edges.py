import os
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PythonEdgeBindingTest(unittest.TestCase):
    def test_binding_in_fresh_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "edges.qdb")
            script = textwrap.dedent(
                f"""
                import sys
                import numpy as np
                sys.path.insert(0, {os.path.join(ROOT, 'python')!r})
                from qihse import VectorDB

                path = {path!r}
                db = VectorDB.create(path, 2)
                db.add_vectors(np.asarray([[1, 0], [0, 1]], dtype=np.float32), ids=[11, 12])
                assert db.add_edge(11, 12, "CALLS", b"line=7")
                assert not db.add_edge(11, 12, "CALLS", b"ignored")
                assert db.neighbors(11, "CALLS") == [12]
                assert db.edge_records(11) == [(11, 12, "CALLS", b"line=7")]
                db.replace_edge(11, 12, "CALLS", b"line=8")
                db.close()

                db = VectorDB.open(path, read_only=True)
                assert db.edge_records(11) == [(11, 12, "CALLS", b"line=8")]
                db.close()
                """
            )
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = ROOT
            completed = subprocess.run(
                [sys.executable, "-c", script], cwd=ROOT, env=env,
                text=True, capture_output=True, timeout=60, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)


if __name__ == "__main__":
    unittest.main()
