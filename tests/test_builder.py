#!/usr/bin/env python3
"""
Unit tests for QIHSE builder.py — validation, CPU detection, UI helpers,
HSM bind prompt, and keygen integration.

Run: python3 tests/test_builder.py
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import builder


class TestValidateMarch(unittest.TestCase):

    def test_valid_known_marches(self):
        for m in ("native", "sandybridge", "haswell", "alderlake",
                   "skylake-avx512", "x86-64", "x86-64-v2", "x86-64-v4"):
            self.assertEqual(builder.validate_march(m), m)

    def test_rejects_shell_metacharacters(self):
        with self.assertRaises(SystemExit):
            builder.validate_march("native; rm -rf /")

    def test_rejects_spaces(self):
        with self.assertRaises(SystemExit):
            builder.validate_march("native -O0")

    def test_rejects_empty(self):
        with self.assertRaises(SystemExit):
            builder.validate_march("")

    def test_allows_dots_and_dashes(self):
        self.assertEqual(builder.validate_march("x86-64-v4"), "x86-64-v4")
        self.assertEqual(builder.validate_march("skylake-avx512"), "skylake-avx512")


class TestValidateAlias(unittest.TestCase):

    def test_valid_names(self):
        for name in ("QIHSE_DB", "MY_VAR", "_private", "A", "VAR_123"):
            self.assertEqual(builder.validate_alias(name), name)

    def test_rejects_semicolon(self):
        with self.assertRaises(SystemExit):
            builder.validate_alias("FOO; rm /")

    def test_rejects_starts_with_digit(self):
        with self.assertRaises(SystemExit):
            builder.validate_alias("1VAR")

    def test_rejects_dollar(self):
        with self.assertRaises(SystemExit):
            builder.validate_alias("$(whoami)")


class TestVisibleLen(unittest.TestCase):

    def test_plain_string(self):
        self.assertEqual(builder.visible_len("hello"), 5)

    def test_ansi_stripped(self):
        s = builder.c("hello", builder.RED)
        self.assertEqual(builder.visible_len(s), 5)

    def test_empty(self):
        self.assertEqual(builder.visible_len(""), 0)


class TestPadRight(unittest.TestCase):

    def test_short_string(self):
        result = builder.pad_right("hi", 10)
        self.assertEqual(builder.visible_len(result), 10)

    def test_exact_width(self):
        result = builder.pad_right("hello", 5)
        self.assertEqual(result, "hello")

    def test_oversized_string(self):
        result = builder.pad_right("hello world", 5)
        self.assertEqual(result, "hello world")


class TestDetectCpu(unittest.TestCase):

    def test_returns_dict_with_required_keys(self):
        feat = builder.detect_cpu()
        required = {"arch", "model", "sse42", "avx", "avx2", "fma",
                    "avx512", "amx", "vnni", "hybrid",
                    "hybrid_pcores", "hybrid_ecores"}
        for key in required:
            self.assertIn(key, feat, f"Missing key: {key}")

    def test_arch_is_string(self):
        feat = builder.detect_cpu()
        self.assertIsInstance(feat["arch"], str)
        self.assertTrue(len(feat["arch"]) > 0)

    def test_boolean_fields(self):
        feat = builder.detect_cpu()
        for key in ("sse42", "avx", "avx2", "fma", "avx512", "amx", "hybrid"):
            self.assertIsInstance(feat[key], bool, f"{key} should be bool")

    def test_avx512_requires_foundation(self):
        feat = builder.detect_cpu()
        if feat["avx512"]:
            self.assertTrue(feat["avx512f"])
            self.assertTrue(feat["avx512dq"])
            self.assertTrue(feat["avx512bw"])
            self.assertTrue(feat["avx512vl"])


class TestArchLabel(unittest.TestCase):

    def test_scalar_fallback(self):
        feat = {"avx512": False, "amx": False, "avx_vnni": False,
                "avx2": False, "avx": False, "sse42": False, "fma": False}
        self.assertEqual(builder.arch_label(feat), "scalar")

    def test_avx2_with_fma(self):
        feat = {"avx512": False, "amx": False, "avx_vnni": False,
                "avx2": True, "avx": True, "sse42": True, "fma": True}
        label = builder.arch_label(feat)
        self.assertIn("AVX2", label)
        self.assertIn("FMA", label)


class TestSafeInput(unittest.TestCase):

    def test_returns_default_on_eof(self):
        with patch("builtins.input", side_effect=EOFError):
            result = builder.safe_input("prompt", "default_val")
            self.assertEqual(result, "default_val")

    def test_returns_input_on_success(self):
        with patch("builtins.input", return_value="user_text"):
            result = builder.safe_input("prompt", "default_val")
            self.assertEqual(result, "user_text")


class TestHsmBindPrompt(unittest.TestCase):
    """Test the 5s HSM bind prompt defaults to SKIP."""

    def test_defaults_to_skip_on_eof(self):
        """When stdin is closed (non-interactive), should skip."""
        with patch("termios.tcgetattr", side_effect=AttributeError):
            result = builder.hsm_bind_prompt()
            self.assertFalse(result, "HSM bind should default to skip")

    def test_defaults_to_skip_on_no_tty(self):
        """When there's no terminal, should skip."""
        import termios
        def raise_error(*args):
            raise termios.error("no tty")
        with patch("termios.tcgetattr", side_effect=raise_error):
            result = builder.hsm_bind_prompt()
            self.assertFalse(result)


class TestBoxAlignment(unittest.TestCase):
    """Test that all box functions produce consistent widths."""

    def test_banner_width(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            builder.banner("TEST")
        lines = [l for l in buf.getvalue().split("\n") if l.strip()]
        for line in lines:
            clean = builder._ANSI_RE.sub("", line)
            self.assertEqual(len(clean), builder.WIDTH + 2,
                             f"Banner line width mismatch: {len(clean)} != {builder.WIDTH + 2}")

    def test_success_box_width(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            builder.success_box("Test message")
        lines = [l for l in buf.getvalue().split("\n") if l.strip()]
        for line in lines:
            clean = builder._ANSI_RE.sub("", line)
            self.assertEqual(len(clean), builder.WIDTH + 2,
                             f"Success box width mismatch: {len(clean)} != {builder.WIDTH + 2}")

    def test_warning_box_width(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            builder.warning_box(["Line 1", "Line 2"])
        lines = [l for l in buf.getvalue().split("\n") if l.strip()]
        for line in lines:
            clean = builder._ANSI_RE.sub("", line)
            self.assertEqual(len(clean), builder.WIDTH + 2,
                             f"Warning box width mismatch: {len(clean)} != {builder.WIDTH + 2}")


class TestBuildTargets(unittest.TestCase):

    def test_all_targets_have_two_elements(self):
        for key, val in builder.BUILD_TARGETS.items():
            self.assertEqual(len(val), 2)

    def test_arch_targets_have_three_elements(self):
        for key, val in builder.TARGETS.items():
            self.assertEqual(len(val), 3)

    def test_native_is_option_1(self):
        self.assertEqual(builder.TARGETS["1"][0], "native")
        self.assertIsNone(builder.TARGETS["1"][2])

    def test_submenu_marker(self):
        self.assertEqual(builder.TARGETS["5"][2], "SUBMENU")

    def test_has_keygen_goal(self):
        goals = [v[0] for v in builder.BUILD_TARGETS.values()]
        self.assertIn("keygen", goals)

    def test_has_server_goal(self):
        goals = [v[0] for v in builder.BUILD_TARGETS.values()]
        self.assertIn("server", goals)


class TestDefaultOutputPath(unittest.TestCase):
    """Test that default output path is the ZFS dataset."""

    def test_default_out_is_zfs(self):
        # The default output path should be /rpool/data/db/qihse
        # We check by inspecting the main() code path
        import inspect
        source = inspect.getsource(builder.main)
        self.assertIn("/rpool/data/db/qihse", source)


class TestKeygenIntegration(unittest.TestCase):
    """Test keygen binary detection logic."""

    def test_keygen_bin_path_check(self):
        """Builder should look for qihse_keygen in ROOT and output bin."""
        # Verify the builder code references qihse_keygen
        import inspect
        source = inspect.getsource(builder.main)
        self.assertIn("qihse_keygen", source)
        self.assertIn("--bind-operator", source)


if __name__ == "__main__":
    unittest.main()
