"""Exercise installed headers and libraries without checkout include paths."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PublicAPIInstall(unittest.TestCase):
    def run_command(self, args, *, cwd=None, env=None, success=True):
        result = subprocess.run(args, cwd=cwd or ROOT, env=env or self.env,
                                text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=300)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stdout

    def setUp(self):
        self.env = os.environ.copy()
        for key in ("MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "CPATH",
                    "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH"):
            self.env.pop(key, None)
        self.env["LD_LIBRARY_PATH"] = str(ROOT) + os.pathsep + self.env.get("LD_LIBRARY_PATH", "")
        self.cc = shlex.split(os.environ.get("CC", "cc"))
        self.cxx = shlex.split(os.environ.get("CXX", "c++"))

    def test_source_vector_header_with_minimal_include_path(self):
        with tempfile.TemporaryDirectory(prefix="qihse-source-header-") as directory:
            source = Path(directory) / "consumer.c"
            source.write_text("#include <qihse_vector_db.h>\n")
            self.run_command(self.cc + ["-std=c11", "-D_GNU_SOURCE", "-Werror",
                "-fsyntax-only", f"-I{ROOT / 'include'}", str(source)], cwd=directory)

    def test_staged_install_and_dependency_failure(self):
        with tempfile.TemporaryDirectory(prefix="qihse-public-api-") as directory:
            work = Path(directory)
            stage = work / "stage"
            prefix = "/public-sdk"
            self.run_command(["make", "--no-print-directory", "install",
                              f"DESTDIR={stage}", f"PREFIX={prefix}"])
            sdk = stage / prefix.lstrip("/")
            headers = sdk / "include"
            default_stage = work / "default stage"
            self.run_command(["make", "--no-print-directory", "install-headers",
                              f"DESTDIR={default_stage}", "PREFIX=/usr/local"])
            self.assertTrue((default_stage / "usr/local/include/qihse/qihse.h").is_file())
            self.assertFalse((stage / "usr/local").exists())
            self.assertFalse((sdk / "src").exists())
            self.assertTrue((sdk / "bin/qihse-backup").is_file())
            self.assertTrue((sdk / "bin/qihse-admin-cli").is_file())
            # Do not let an omitted SQL/pgwire root silently skip its compile check.
            required = {"qihse.h", "qihse_auth_maintenance.h", "qihse_schema.h", "qihse_table_store.h",
                        "qihse_sql_parser.h", "qihse_sql_extensions.h",
                        "qihse_sql_fts.h", "qihse_sql_row_index.h",
                        "qihse_uwp_sql_txn_schema.h", "qihse_pg_wire.h",
                        "qihse_cluster_slot.h", "qihse_crc16.h",
                        "qihse_kv_store.h"}
            installed = {header.name for header in (headers / "qihse").glob("*.h")}
            self.assertTrue(required <= installed, f"Missing headers: {required - installed}")
            # Compile roots separately: legacy qihse.h and SQL enums are distinct APIs.
            for name in sorted(installed):
                source = work / "header.c"
                source.write_text(f"#include <qihse/{name}>\n")
                self.run_command(self.cc + ["-std=c11", "-D_GNU_SOURCE", "-Werror",
                                 "-fsyntax-only", f"-I{headers}", str(source)], cwd=work)
            source = work / "consumer.c"
            shutil.copyfile(ROOT / "tests/public_api_install_smoke.c", source)
            consumer = work / "consumer"
            library = sdk / "lib"
            self.run_command(self.cc + ["-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                             "-Werror", f"-I{headers}", str(source), f"-L{library}",
                             f"-Wl,-rpath-link,{ROOT}", "-lqihse", "-o", str(consumer)], cwd=work)
            runtime = self.env.copy()
            runtime["LD_LIBRARY_PATH"] = str(library) + os.pathsep + runtime["LD_LIBRARY_PATH"]
            self.assertIn("consumer: OK", self.run_command([str(consumer)], cwd=work, env=runtime))
            dependencies = self.run_command(["ldd", str(consumer)], cwd=work, env=runtime)
            self.assertNotIn("not found", dependencies)
            self.assertIn(str(library / "libqihse.so"), dependencies)
            # Keep the KV C++ root separate from legacy/SQL namespace conflicts.
            cpp_source = work / "kv_consumer.cpp"
            cpp_source.write_text(
                '#include <qihse/qihse_kv_store.h>\n'
                '#include <qihse/qihse_auth_maintenance.h>\n'
                'int main() {\n'
                '    qihse_auth_maintenance_status_t (*volatile capabilities)(\n'
                '        const qihse_user_t *, qihse_auth_maintenance_caps_t *) =\n'
                '        qihse_auth_maintenance_capabilities;\n'
                '    if (!capabilities) return 2;\n'
                '    qihse_kv_store_t *(*volatile create_user)(qihse_user_t *) =\n'
                '        qihse_kv_store_create_user;\n'
                '    return create_user ? 0 : 1;\n'
                '}\n')
            cpp_consumer = work / "kv_consumer"
            self.run_command(self.cxx + ["-std=c++11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                             "-Werror", f"-I{headers}", str(cpp_source), f"-L{library}",
                             f"-Wl,-rpath-link,{ROOT}", "-lqihse", "-o", str(cpp_consumer)],
                             cwd=work)
            self.run_command([str(cpp_consumer)], cwd=work, env=runtime)
            cpp_dependencies = self.run_command(["ldd", str(cpp_consumer)], cwd=work, env=runtime)
            self.assertNotIn("not found", cpp_dependencies)
            self.assertIn(str(library / "libqihse.so"), cpp_dependencies)
            self.run_command(["bash", str(ROOT / "scripts/install_qihse.sh"),
                              "--check-dependencies"], cwd=work, env=runtime)
            # Shadow the SONAME: the real loader must reject the broken dependency.
            missing = work / "missing"
            missing.mkdir()
            (missing / "libstemmer.so.0d").write_text("not an ELF shared library\n")
            broken = runtime.copy()
            broken["LD_LIBRARY_PATH"] = str(missing) + os.pathsep + runtime["LD_LIBRARY_PATH"]
            for command in (["make", "--no-print-directory", "check-runtime-deps"],
                            ["bash", str(ROOT / "scripts/install_qihse.sh"), "--check-dependencies"]):
                output = self.run_command(command, env=broken, success=False)
                self.assertIn("libstemmer.so.0d unavailable", output)
                self.assertIn("Install libstemmer0d", output)
            self.run_command([str(consumer), "missing-stemmer"], cwd=work, env=broken)
            # A loadable but incompatible library must fail the symbol check too.
            shim = work / "shim.c"
            shim.write_text("int not_a_stemmer(void) { return 0; }\n")
            self.run_command(self.cc + ["-shared", "-fPIC", str(shim), "-o",
                                      str(missing / "libstemmer.so.0d")], cwd=work)
            output = self.run_command(["make", "--no-print-directory", "check-runtime-deps"],
                                      env=broken, success=False)
            self.assertIn("sb_stemmer_new", output)
            self.run_command([str(consumer), "missing-stemmer"], cwd=work, env=broken)


if __name__ == "__main__":
    unittest.main(verbosity=2)
