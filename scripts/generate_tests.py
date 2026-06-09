import sys
import json
import os
sys.path.append(os.path.abspath("VectorReVamp"))

from unified_test_harness.qihse_db_plugin import QihseDatabasePlugin

plugin = QihseDatabasePlugin()
tests = plugin.generate_domain_tests([], "qihse")

with open("sdks/python/test_all_dbs.py", "w") as f:
    for t in tests:
        f.write(t["code"])
        f.write("\n")

print("Generated sdks/python/test_all_dbs.py successfully.")
