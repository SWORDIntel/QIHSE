#!/usr/bin/env python3
"""Browser unit tests: slot math, action validation, WebAuthn RP.

The WebAuthn tests verify the relying party against synthetic ceremonies
built with a locally-generated ES256 key — no hardware authenticator is
needed, and the assertions still cross the same code path a real YubiKey
uses (rp_id_hash, UP+UV flags, sign_count monotonicity, ECDSA signature
over authData || SHA256(clientDataJSON), origin/type/challenge checks).

Run from the repo root:  PYTHONPATH=python python3 python/tests/test_browser_unit.py
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "python"))

from fido2 import cbor                                   # noqa: E402
from fido2.webauthn import AuthenticatorData              # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives import hashes         # noqa: E402

from qihse.browser.slots import keyslot, crc16, hash_tag  # noqa: E402
from qihse.browser import actions as actions_mod          # noqa: E402
from qihse.browser.fleet import NodeSpec, SessionFleet    # noqa: E402
from qihse.browser.webauthn import (                      # noqa: E402
    RelyingParty, CredentialStore, WebAuthnError, b64u,
)

PASS = 0


def ok(name: str, cond: bool, detail: str = ""):
    global PASS
    if not cond:
        raise AssertionError(f"[FAIL] {name} {detail}")
    PASS += 1
    print(f"[PASS] {name}")


# ── slots ───────────────────────────────────────────────────────────────────

def test_slots():
    # Vectors cross-checked against redis CLUSTER KEYSLOT documentation.
    ok("keyslot foo == 12182", keyslot("foo") == 12182)
    ok("keyslot bar == 5061", keyslot("bar") == 5061)
    ok("keyslot hello == 866", keyslot("hello") == 866)
    ok("crc16('123456789') == 0x31C3", crc16(b"123456789") == 0x31C3)
    ok("hash-tag semantics", keyslot("{user}.following") == keyslot("user"))
    ok("no-tag fallback", keyslot("user.following") != keyslot("user.followin_"))
    ok("empty braces fall back to whole key",
       keyslot("{}foo") == crc16(b"{}foo") % 16384
       and keyslot("{}foo") != keyslot("foo"))
    ok("bytes/str parity", keyslot(b"foo") == keyslot("foo"))


# ── actions ─────────────────────────────────────────────────────────────────

def test_actions():
    fleet = SessionFleet([NodeSpec("127.0.0.1", 7100),
                          NodeSpec("10.0.0.5", 7101)], "u", "p")

    c, w = actions_mod.REGISTRY["moveslots"].canonical(
        fleet, {"first": 0, "last": 100, "target": "10.0.0.5:7101"})
    ok("moveslots canonical", c == "CLUSTER MOVESLOTS 0-100 10.0.0.5:7101", c)
    ok("moveslots wire", w == ["CLUSTER", "MOVESLOTS", "0-100", "10.0.0.5:7101"])

    def refused(name, fn):
        try:
            fn()
            raise AssertionError(f"[FAIL] {name} was not refused")
        except actions_mod.ActionError:
            ok(name, True)

    refused("slot bounds enforced",
            lambda: actions_mod.canonical_for(fleet, "moveslots",
                                              {"first": 0, "last": 99999,
                                               "target": "10.0.0.5:7101"}))
    refused("first<=last enforced",
            lambda: actions_mod.canonical_for(fleet, "moveslots",
                                              {"first": 10, "last": 5,
                                               "target": "10.0.0.5:7101"}))
    refused("unseeded target refused",
            lambda: actions_mod.canonical_for(fleet, "moveslots",
                                              {"first": 0, "last": 1,
                                               "target": "evil.example:9999"}))
    refused("bad uuid refused",
            lambda: actions_mod.canonical_for(fleet, "trust_set",
                                              {"uuid": "nothex", "state": "APPROVED",
                                               "result": "attested"}))
    refused("bad state enum refused",
            lambda: actions_mod.canonical_for(fleet, "trust_set",
                                              {"uuid": "a" * 32, "state": "GOD",
                                               "result": "attested"}))
    refused("unknown action refused",
            lambda: actions_mod.canonical_for(fleet, "shutdown", {}))
    refused("fed_state enum",
            lambda: actions_mod.canonical_for(fleet, "fed_state",
                                              {"state": "OPEN"}))
    # new control-surface validators
    fleet_ops = SessionFleet([NodeSpec("10.0.0.9", 7100)], "u", "p")
    for name, args, want in [
        ("node_approve", {"uuid": "ab" * 16},
         f"FEDERATION NODE.APPROVE {'ab'*16}"),
        ("node_revoke", {"uuid": "cd" * 16},
         f"FEDERATION NODE.REVOKE {'cd'*16}"),
        ("lease_renew", {"lease_id": "L-42"}, "FEDERATION LEASE.RENEW L-42"),
        ("ns_register", {"name": "fleet", "class": "quorum"},
         "FEDERATION NS.REGISTER fleet QUORUM"),
        ("bgsave", {}, "BGSAVE"),
    ]:
        c, _ = actions_mod.REGISTRY[name].canonical(fleet_ops, args)
        ok(f"{name} canonical", c == want, c)
    refused("ns_register bad class",
            lambda: actions_mod.canonical_for(
                fleet_ops, "ns_register", {"name": "x", "class": "FAST"}))

    # extra-actions file: validated extension, forbids fatal commands
    import json as _json
    import os as _os
    with tempfile.TemporaryDirectory() as d:
        good = _os.path.join(d, "extra.json")
        _open = open(good, "w")
        _open.write(_json.dumps([
            {"name": "repl_pull", "title": "Pull a replicated namespace",
             "command": ["REPL.PULL", "$glob"],
             "params": {"glob": {"type": "string", "max": 128}}}]))
        _open.close()
        n = actions_mod.load_extra(good, log=lambda m: None)
        ok("extra action loaded", n == 1 and "repl_pull" in actions_mod.REGISTRY)
        c, w = actions_mod.REGISTRY["repl_pull"].canonical(
            fleet_ops, {"glob": "fleet/*"})
        ok("extra action canonical + wire",
           c == "REPL.PULL fleet/*" and w == ["REPL.PULL", "fleet/*"], c)
        refused("extra action arg cap enforced",
                lambda: actions_mod.canonical_for(
                    fleet_ops, "repl_pull", {"glob": "x" * 200}))
        fatal = _os.path.join(d, "fatal.json")
        _open = open(fatal, "w")
        _open.write(_json.dumps([{"command": ["SHUTDOWN"]}]))
        _open.close()
        try:
            actions_mod.load_extra(fatal, log=lambda m: None)
            raise AssertionError("[FAIL] SHUTDOWN accepted as extra action")
        except actions_mod.ActionError as exc:
            ok("SHUTDOWN refused in extra actions", exc.code == "FORBIDDEN_ACTION")
        del actions_mod.REGISTRY["repl_pull"]

    c2, _ = actions_mod.REGISTRY["trust_set"].canonical(
        fleet, {"uuid": "AB" * 16, "state": "approved", "result": "attested"})
    ok("uuid lowercased + state upper",
       c2 == f"FEDERATION TRUST.SET {'ab'*16} APPROVED attested", c2)


# ── WebAuthn RP against synthetic ceremonies ────────────────────────────────

UP_UV = 0x01 | 0x04


def synth_auth_data(rp_id_hash: bytes, sign_count: int,
                    attested: tuple | None = None) -> bytes:
    """Build wire-exact authenticator data. AT flag set only when the
    record carries attested credential data (fido2 parses strictly)."""
    from fido2.webauthn import AuthenticatorData as AD
    cred_bytes = b""
    flags = UP_UV
    if attested is not None:
        cred_id, cose_key = attested
        flags |= 0x40                                # AT
        cred_bytes = (b"\x00" * 16                  # zero AAGUID
                      + struct.pack(">H", len(cred_id)) + cred_id
                      + cbor.encode(cose_key))
    return bytes(AD.create(rp_id_hash, flags, sign_count, cred_bytes))


def synth_cose_key(priv) -> dict:
    nums = priv.public_key().public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    return {1: 2, 3: -7, -1: 1, -2: x, -3: y}      # EC2 / ES256 / P-256


def client_data(rp: RelyingParty, ctype: str, challenge: str,
                origin: str | None = None) -> bytes:
    return json.dumps({
        "type": ctype,
        "challenge": challenge,
        "origin": origin or "http://localhost:8090",
        "crossOrigin": False,
    }).encode()


def test_webauthn():
    priv = ec.generate_private_key(ec.SECP256R1())
    cose_key = synth_cose_key(priv)
    rp = RelyingParty(8090)

    with tempfile.TemporaryDirectory() as d:
        store = CredentialStore(os.path.join(d, "creds.json"))

        # -- enrollment --
        enroll_opts = rp.begin_enroll("GODMODE_OP", "sess1")
        ch = enroll_opts["publicKey"]["challenge"]
        cred_id = b"\x01 synthetic-yubikey \x02"
        auth_data = synth_auth_data(rp.rp_id_hash, 5, attested=(cred_id, cose_key))
        att_obj = cbor.encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cd = client_data(rp, "webauthn.create", ch)
        cred = {"id": b64u(cred_id),
                "rawId": b64u(cred_id),
                "_challenge": ch,
                "response": {"clientDataJSON": b64u(cd),
                             "attestationObject": b64u(att_obj)}}
        enrolled = rp.verify_enroll("GODMODE_OP", "sess1", cred)
        store.put(enrolled)
        ok("enroll ok", store.get(b64u(cred_id)) is not None)
        ok("enroll sign_count captured", enrolled.sign_count == 5)
        ok("enroll records aaguid", enrolled.aaguid == "00000000-0000-0000-0000-000000000000")

        # replayed enrollment challenge must fail (single-use)
        try:
            rp.verify_enroll("GODMODE_OP", "sess1", cred)
            raise AssertionError("[FAIL] challenge reuse accepted")
        except WebAuthnError as exc:
            ok("enroll challenge single-use", exc.code == "BAD_CHALLENGE")

        # -- login assertion --
        login_opts = rp.begin_login(store, "GODMODE_OP", "sess2")
        ch2 = login_opts["publicKey"]["challenge"]
        ad = synth_auth_data(rp.rp_id_hash, 6)
        cd2 = client_data(rp, "webauthn.get", ch2)
        msg = ad + hashlib.sha256(cd2).digest()
        sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
        assertion = {"id": b64u(cred_id), "_challenge": ch2,
                     "response": {"clientDataJSON": b64u(cd2),
                                  "authenticatorData": b64u(ad),
                                  "signature": b64u(sig)}}
        rp.verify_login(store, "GODMODE_OP", "sess2", assertion)
        ok("login assertion verifies", store.get(b64u(cred_id)).sign_count == 6)

        # tampered signature must fail
        login3 = rp.begin_login(store, "GODMODE_OP", "sess3")
        ch3 = login3["publicKey"]["challenge"]
        bad = bytearray(sig)
        bad[10] ^= 0xFF
        bad_sig = bytes(bad)
        ad3 = synth_auth_data(rp.rp_id_hash, 7)
        cd3 = client_data(rp, "webauthn.get", ch3)
        msg3 = ad3 + hashlib.sha256(cd3).digest()
        # sign correctly but then swap in the tampered signature
        real_sig = priv.sign(msg3, ec.ECDSA(hashes.SHA256()))
        del real_sig
        t = {"id": b64u(cred_id), "_challenge": ch3,
             "response": {"clientDataJSON": b64u(cd3),
                          "authenticatorData": b64u(ad3),
                          "signature": b64u(bad_sig)}}
        try:
            rp.verify_login(store, "GODMODE_OP", "sess3", t)
            raise AssertionError("[FAIL] tampered signature accepted")
        except WebAuthnError as exc:
            ok("tampered signature refused", exc.code == "BAD_SIGNATURE")

        # wrong-origin client data must fail
        login4 = rp.begin_login(store, "GODMODE_OP", "sess4")
        ch4 = login4["publicKey"]["challenge"]
        ad4 = synth_auth_data(rp.rp_id_hash, 8)
        cd4 = client_data(rp, "webauthn.get", ch4, origin="https://evil.example")
        msg4 = ad4 + hashlib.sha256(cd4).digest()
        sig4 = priv.sign(msg4, ec.ECDSA(hashes.SHA256()))
        t4 = {"id": b64u(cred_id), "_challenge": ch4,
              "response": {"clientDataJSON": b64u(cd4),
                           "authenticatorData": b64u(ad4),
                           "signature": b64u(sig4)}}
        try:
            rp.verify_login(store, "GODMODE_OP", "sess4", t4)
            raise AssertionError("[FAIL] foreign origin accepted")
        except WebAuthnError as exc:
            ok("foreign origin refused", exc.code == "BAD_ORIGIN")

        # non-increasing sign_count must fail (clone detection)
        login5 = rp.begin_login(store, "GODMODE_OP", "sess5")
        ch5 = login5["publicKey"]["challenge"]
        ad5 = synth_auth_data(rp.rp_id_hash, 6)     # <= stored 6
        cd5 = client_data(rp, "webauthn.get", ch5)
        msg5 = ad5 + hashlib.sha256(cd5).digest()
        sig5 = priv.sign(msg5, ec.ECDSA(hashes.SHA256()))
        t5 = {"id": b64u(cred_id), "_challenge": ch5,
              "response": {"clientDataJSON": b64u(cd5),
                           "authenticatorData": b64u(ad5),
                           "signature": b64u(sig5)}}
        try:
            rp.verify_login(store, "GODMODE_OP", "sess5", t5)
            raise AssertionError("[FAIL] replayed sign_count accepted")
        except WebAuthnError as exc:
            ok("non-increasing sign_count refused", exc.code == "CLONE_SUSPECTED")

        # no UV flag must fail
        login6 = rp.begin_login(store, "GODMODE_OP", "sess6")
        ch6 = login6["publicKey"]["challenge"]
        ad6 = rp.rp_id_hash + bytes([0x01]) + struct.pack(">I", 9)   # UP only
        cd6 = client_data(rp, "webauthn.get", ch6)
        msg6 = ad6 + hashlib.sha256(cd6).digest()
        sig6 = priv.sign(msg6, ec.ECDSA(hashes.SHA256()))
        t6 = {"id": b64u(cred_id), "_challenge": ch6,
              "response": {"clientDataJSON": b64u(cd6),
                           "authenticatorData": b64u(ad6),
                           "signature": b64u(sig6)}}
        try:
            rp.verify_login(store, "GODMODE_OP", "sess6", t6)
            raise AssertionError("[FAIL] no-UV assertion accepted")
        except WebAuthnError as exc:
            ok("no-UV assertion refused", exc.code == "NO_UV")

        # assertion from a credential enrolled for ANOTHER user must fail
        # (step-2 must bind to step-1's identity)
        ad7 = synth_auth_data(rp.rp_id_hash, 10)
        cd7 = client_data(rp, "webauthn.get", ch6)   # any valid challenge frame
        # issue a fresh one properly
        login7 = rp.begin_login(store, "GODMODE_OP", "sess7")
        ch7 = login7["publicKey"]["challenge"]
        ad7 = synth_auth_data(rp.rp_id_hash, 10)
        cd7 = client_data(rp, "webauthn.get", ch7)
        msg7 = ad7 + hashlib.sha256(cd7).digest()
        sig7 = priv.sign(msg7, ec.ECDSA(hashes.SHA256()))
        t7 = {"id": b64u(cred_id), "_challenge": ch7,
              "response": {"clientDataJSON": b64u(cd7),
                           "authenticatorData": b64u(ad7),
                           "signature": b64u(sig7)}}
        try:
            rp.verify_login(store, "someone_else", "sess7", t7)
            raise AssertionError("[FAIL] cross-user assertion accepted")
        except WebAuthnError as exc:
            ok("cross-user assertion refused", exc.code == "BAD_CHALLENGE")

        # action challenge binding: verified for the SAME command,
        # refused for a DIFFERENT one
        act = rp.begin_action("GODMODE_OP", "sess8",
                              "FEDERATION STATE MAINTENANCE")
        chA = act["publicKey"]["challenge"]
        adA = synth_auth_data(rp.rp_id_hash, 11)
        cdA = client_data(rp, "webauthn.get", chA)
        sigA = priv.sign(adA + hashlib.sha256(cdA).digest(), ec.ECDSA(hashes.SHA256()))
        assA = {"id": b64u(cred_id), "_challenge": chA,
                "response": {"clientDataJSON": b64u(cdA),
                             "authenticatorData": b64u(adA),
                             "signature": b64u(sigA)}}
        rp.verify_action(store, "GODMODE_OP", "sess8",
                         "FEDERATION STATE MAINTENANCE", assA)
        ok("command-bound action assertion verifies",
           store.get(b64u(cred_id)).sign_count == 11)

        act2 = rp.begin_action("GODMODE_OP", "sess9",
                               "CLUSTER MOVESLOTS 0-100 10.0.0.5:7101")
        chB = act2["publicKey"]["challenge"]
        adB = synth_auth_data(rp.rp_id_hash, 12)
        cdB = client_data(rp, "webauthn.get", chB)
        sigB = priv.sign(adB + hashlib.sha256(cdB).digest(), ec.ECDSA(hashes.SHA256()))
        assB = {"id": b64u(cred_id), "_challenge": chB,
                "response": {"clientDataJSON": b64u(cdB),
                             "authenticatorData": b64u(adB),
                             "signature": b64u(sigB)}}
        try:
            rp.verify_action(store, "GODMODE_OP", "sess9",
                             "FEDERATION STATE CONNECTED", assB)
            raise AssertionError("[FAIL] action assertion bound to a "
                                 "different command was accepted")
        except WebAuthnError as exc:
            ok("swapped-command assertion refused", exc.code == "COMMAND_MISMATCH")

        # store integrity: 0600 on save
        ok("credential store is 0600",
           (os.stat(store.path).st_mode & 0o777) == 0o600,
           oct(os.stat(store.path).st_mode))


if __name__ == "__main__":
    test_slots()
    test_actions()
    test_webauthn()
    print(f"\ntest_browser_unit: {PASS} checks passed")
