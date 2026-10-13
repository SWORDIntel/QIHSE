#!/usr/bin/env python3
"""test_dalvik_bug_patterns.py — DEX/Android bug-pattern detector contract.

DalvikBugPatterns.java (pipeline stage "dalvik-bug-patterns", reached via
``universal_decompile.py <classes.dex> --profile dex``) turns three proven
mobile bug-hunt shapes into pipeline rules:

  DEX.RNG.WEAK       new java.util.Random() CONSTRUCTIONS (invoke-direct to
                     java::util::Random::<init>). Method REFERENCES must not
                     match: SecureRandom dispatches nextInt/nextLong through
                     Random's method table, so a ref-based matcher would
                     false-positive on every SecureRandom user.
  DEX.TLS.TRUSTALL   checkServerTrusted overrides with a trivial body.
  DEX.KEY.HARDCODED  SecretKeySpec(byte[],...) with a constant-fed array
                     (honest proximity heuristic: LOW/MEDIUM confidence,
                     reason string in the description).

The fixture (tests/fixtures/dex/) is a synthetic 6-class DEX built with
javac --release 8 + d8 (see tests/fixtures/dex/build_dex.sh). It contains
NO case/sample content. Classes:

  com.kp14.synthetic.transport.SessionKeyFactory  weak RNG in a transport
      package            -> DEX.RNG.WEAK severity HIGH
  com.kp14.synthetic.ui.AnimationJitter          weak RNG in a UI package
                          -> DEX.RNG.WEAK severity MEDIUM
  com.kp14.synthetic.net.TrustAllManager         empty checkServerTrusted
                          -> DEX.TLS.TRUSTALL HIGH/HIGH (2/2 siblings)
  com.kp14.synthetic.crypto.StaticKeyVault       SecretKeySpec over a
      fill-array-data byte[] (via internal aesKeyBytes())
                          -> DEX.KEY.HARDCODED confidence MEDIUM
  com.kp14.synthetic.crypto.DerivedKeyCrypto.derivedKey
                          key bytes mixed from params + constants
                          -> DEX.KEY.HARDCODED confidence LOW (proximity)
  com.kp14.synthetic.crypto.DerivedKeyCrypto.fromString
                          key bytes from String.getBytes (external producer)
                          -> NO finding
  com.kp14.synthetic.crypto.GoodCrypto           SecureRandom ONLY
                          -> NO finding (required negative control)

The test runs the detector standalone through analyzeHeadless (import +
auto-analysis + postScript), the same script-path and isolated-user-home
arrangement universal_decompile.py uses. Skips cleanly when no Ghidra
installation is present.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_DIR / "scripts" / "ghidra"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dex" / "classes.dex"

GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))
ANALYZE = GHIDRA_HOME / "support" / "analyzeHeadless"

REQUIRED_KEYS = {"ruleId", "rva", "function", "severity", "confidence", "description"}


def _findings_by(finding_lines, rule):
    return [f for f in finding_lines if f["ruleId"] == rule]


class DalvikBugPatternTests(unittest.TestCase):
    """Headless detector contract on the synthetic DEX fixture."""

    @classmethod
    def setUpClass(cls):
        if not ANALYZE.is_file():
            raise unittest.SkipTest(f"Ghidra not found at {GHIDRA_HOME} "
                                    "(set GHIDRA_HOME)")
        if not FIXTURE.is_file():
            raise unittest.SkipTest(f"fixture missing: {FIXTURE}")
        cls.tmp = tempfile.TemporaryDirectory(prefix="dalvik-patterns-")
        root = Path(cls.tmp.name)
        cls.out_dir = root / "out"
        cls.out_dir.mkdir()
        findings = cls.out_dir / "findings.jsonl"
        env = dict(os.environ)
        # Isolated user.home + tmpdir: the OSGi script-bundle cache cannot
        # share state across runs (same discipline as universal_decompile.py).
        env["_JAVA_OPTIONS"] = (f"-Duser.home={root / 'home'} "
                                f"-Djava.io.tmpdir={root / 'tmp'}")
        (root / "home").mkdir()
        (root / "tmp").mkdir()
        cmd = [
            str(ANALYZE), str(root), "DalvikTest",
            "-import", str(FIXTURE),
            "-scriptPath", str(SCRIPTS),
            "-postScript", "DalvikBugPatterns.java",
            str(cls.out_dir), str(findings),
            "-deleteProject",
        ]
        proc = subprocess.run(cmd, env=env, capture_output=True,
                              text=True, timeout=600)
        log = proc.stdout + proc.stderr
        if "SCRIPT ERROR" in log or proc.returncode != 0:
            # Keep the log visible for triage before failing assertions.
            print(log[-4000:])
        cls.log = log
        cls.findings = []
        if findings.is_file():
            for line in findings.read_text().splitlines():
                if line.strip():
                    cls.findings.append(json.loads(line))
        cls.sidecar = cls.out_dir / "dalvik_bug_patterns.json"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    # -- shape ----------------------------------------------------------

    def test_detector_ran(self):
        self.assertIn("[DalvikPatterns]", self.log)
        self.assertIn("findings=", self.log)  # detector summary line printed

    def test_every_finding_has_pipeline_shape(self):
        self.assertTrue(self.findings, "detector produced no findings")
        for f in self.findings:
            self.assertTrue(REQUIRED_KEYS <= set(f), f"missing keys: {f}")
            self.assertTrue(f["rva"].startswith("0x"), f)
            self.assertIn(f["severity"], {"HIGH", "MEDIUM", "LOW"}, f)
            self.assertIn(f["confidence"], {"HIGH", "MEDIUM", "LOW"}, f)
            # owning class path must be present (trailing additive key)
            self.assertIn("class", f)
            self.assertIn("evidence", f)
            self.assertTrue(f["class"].startswith("com::kp14::synthetic"), f)

    def test_sidecar_valid_and_counts_match(self):
        self.assertTrue(self.sidecar.is_file())
        sc = json.loads(self.sidecar.read_text())
        self.assertEqual(sc["status"], "ok")
        self.assertEqual(sc["program_format"], "Dalvik Executable (DEX)")
        total = sum(sc["rule_counts"].values())
        self.assertEqual(total, len(self.findings))

    # -- DEX.RNG.WEAK ----------------------------------------------------

    def test_rng_transport_package_is_high(self):
        hits = _findings_by(self.findings, "DEX.RNG.WEAK")
        self.assertEqual(len(hits), 2, self.findings)
        transport = [f for f in hits if "transport" in f["class"]]
        self.assertEqual(len(transport), 1, hits)
        self.assertEqual(transport[0]["severity"], "HIGH")
        self.assertEqual(transport[0]["confidence"], "HIGH")
        self.assertEqual(transport[0]["function"],
                         "com::kp14::synthetic::transport::SessionKeyFactory"
                         "::nextSessionToken")

    def test_rng_ui_package_is_medium(self):
        ui = [f for f in _findings_by(self.findings, "DEX.RNG.WEAK")
              if "ui" in f["class"]]
        self.assertEqual(len(ui), 1)
        self.assertEqual(ui[0]["severity"], "MEDIUM")

    def test_rng_counts_constructions_only(self):
        # GoodCrypto calls nextInt through Random's method table on a
        # SecureRandom instance: a ref-based matcher would fire here.
        good = [f for f in self.findings if "GoodCrypto" in f["function"]]
        self.assertEqual(good, [], "SecureRandom control must stay clean")

    # -- DEX.TLS.TRUSTALL -------------------------------------------------

    def test_trustall_fires_on_empty_check_server_trusted(self):
        hits = _findings_by(self.findings, "DEX.TLS.TRUSTALL")
        self.assertEqual(len(hits), 1, self.findings)
        f = hits[0]
        self.assertTrue(f["function"].endswith("::checkServerTrusted"), f)
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["confidence"], "HIGH")  # 2/2 siblings corroborate
        self.assertIn("X509TrustManager", f["description"])

    # -- DEX.KEY.HARDCODED --------------------------------------------------

    def test_key_medium_on_fill_array_data_chain(self):
        hits = _findings_by(self.findings, "DEX.KEY.HARDCODED")
        medium = [f for f in hits if f["confidence"] == "MEDIUM"]
        self.assertEqual(len(medium), 1, hits)
        f = medium[0]
        self.assertTrue(f["function"].endswith("StaticKeyVault::keySpec"), f)
        self.assertIn("fill-array-data", f["description"])
        self.assertIn("proximity heuristic", f["description"])

    def test_key_low_is_proximity_only(self):
        hits = _findings_by(self.findings, "DEX.KEY.HARDCODED")
        low = [f for f in hits if f["confidence"] == "LOW"]
        self.assertEqual(len(low), 1, hits)
        self.assertTrue(low[0]["function"].endswith("DerivedKeyCrypto::derivedKey"))
        self.assertIn("proximity heuristic", low[0]["description"])
        # LOW tier must never claim proof
        self.assertNotIn("proof", low[0]["description"].replace("not a proof", ""))

    def test_key_clean_when_array_from_runtime_string(self):
        # fromString: SecretKeySpec over String.getBytes output — external
        # producer, no constant material visible. Must NOT fire at all.
        hits = [f for f in self.findings if "fromString" in f["function"]]
        self.assertEqual(hits, [], "external-producer control must stay clean")


if __name__ == "__main__":
    unittest.main()
