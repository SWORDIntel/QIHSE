#!/usr/bin/env python3
"""Regression tests for dependency build failure and artifact verification."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BuildVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.prefix = self.root / "prefix"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.root / "benchmarks").mkdir()
        (self.root / "benchmarks/w12.mk").write_text("")
        (self.root / "quantization").mkdir()
        (self.root / "quantization/w12.mk").write_text("")
        self.vendor = self.root / "vendor" / "liboqs"
        self.vendor.mkdir(parents=True)
        (self.vendor / "CMakeLists.txt").write_text("# fake project\n")
        self._tool("cmake", '''#!/bin/sh
[ "${FAIL_TOOL:-}" = cmake ] && exit 31
echo fake-cmake
exit 0
''')
        self._tool("ninja", '''#!/bin/sh
[ "${FAIL_TOOL:-}" = "ninja-$1" ] && exit 32
case "$1" in
  install)
    [ "${OMIT_CONFIG:-}" = 1 ] || mkdir -p "$PREFIX/lib/cmake/liboqs"
    [ "${OMIT_CONFIG:-}" = 1 ] || printf 'set(liboqs_FOUND TRUE)\n' > "$PREFIX/lib/cmake/liboqs/liboqsConfig.cmake"
    mkdir -p "$PREFIX/lib"
    printf 'usable\n' > "$PREFIX/lib/liboqs.so"
    ;;
  *)
    mkdir -p lib
    printf 'usable\n' > lib/liboqs.so
    [ "${OMIT_CONFIG:-}" = 1 ] || mkdir -p lib/cmake/liboqs
    [ "${OMIT_CONFIG:-}" = 1 ] || printf 'set(liboqs_FOUND TRUE)\n' > lib/cmake/liboqs/liboqsConfig.cmake
    ;;
esac
''')
        self._tool("ldd", '''#!/bin/sh
for artifact do :; done
grep -q usable "$artifact"
''')
        self._tool("openssl", '''#!/bin/sh
[ "${FAKE_PROVIDER_LOAD:-1}" = 1 ] || exit 1
printf 'oqsprovider\\n  status: active\\n'
''')
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.env["PREFIX"] = str(self.prefix)

    def tearDown(self):
        self.tmp.cleanup()

    def _tool(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def _run(self, target="liboqs", **env):
        return subprocess.run(
            ["make", "-f", str(ROOT / "Makefile"), target,
             f"QIHSE_DEPS_PREFIX={self.prefix}"],
            cwd=self.root, env={**self.env, **env}, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

    def test_success_requires_config_and_installs_artifacts_under_prefix(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue((self.prefix / "lib/liboqs.so").is_file())
        self.assertTrue((self.prefix / "lib/cmake/liboqs/liboqsConfig.cmake").is_file())

    def test_cmake_failure_is_propagated(self):
        self.assertNotEqual(self._run(FAIL_TOOL="cmake").returncode, 0)

    def test_ninja_build_failure_is_propagated(self):
        self.assertNotEqual(self._run(FAIL_TOOL="ninja-").returncode, 0)

    def test_ninja_install_failure_is_propagated(self):
        self.assertNotEqual(self._run(FAIL_TOOL="ninja-install").returncode, 0)

    def test_missing_package_config_fails_verification(self):
        result = self._run(OMIT_CONFIG="1")
        self.assertNotEqual(result.returncode, 0)

    def test_nonempty_library_without_package_config_is_not_ready(self):
        (self.prefix / "lib").mkdir(parents=True)
        (self.prefix / "lib/liboqs.so").write_text("usable\\n")
        result = self._run(OMIT_CONFIG="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("liboqs package ready", result.stdout)

    def test_provider_requires_successful_openssl_load(self):
        (self.prefix / "lib/cmake/liboqs").mkdir(parents=True)
        (self.prefix / "lib/liboqs.so").write_text("usable\\n")
        (self.prefix / "lib/cmake/liboqs/liboqsConfig.cmake").write_text("set(liboqs_FOUND TRUE)\\n")
        module = self.prefix / "lib/ossl-modules/oqsprovider.so"
        module.parent.mkdir(parents=True)
        module.write_text("usable\\n")
        ready = self._run("oqs-provider")
        self.assertEqual(ready.returncode, 0, ready.stdout)
        self.assertIn("oqs-provider usable", ready.stdout)
        failed = self._run("oqs-provider", FAKE_PROVIDER_LOAD="0")
        self.assertNotEqual(failed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
