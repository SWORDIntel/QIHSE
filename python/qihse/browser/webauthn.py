"""WebAuthn relying party for the browser bridge (python-fido2 + cryptography).

Design points from the plan review:

    * RP ID is ``localhost`` — browsers reject IP-literal RP IDs, and the
      bridge is loopback-only, so ``http://localhost:<port>`` (directly or
      via SSH -L) is a secure context without TLS certificates.
    * UV (PIN + touch) is REQUIRED on every ceremony; UP implied.
    * Only cross-platform authenticators may enroll (no synced/platform
      passkeys); AAGUID is recorded and can be pinned via allow-list file.
    * sign_count is persisted and must increase — clone detection.
    * The credential store holds PUBLIC key material only; writing it is
      the sensitive operation, so enrollment requires an authenticated
      session and is restricted (self-enroll, or system principal).
    * With --require-webauthn (default), a username with NO enrolled
      credential FAILS login — "no credential" is not a single-factor
      mode.  Deleting the store bricks logins (fail-closed DoS), it does
      not downgrade them.
    * Every challenge is single-use, short-TTL, and bound server-side to
      its purpose (login session / exact action command / enrollment).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field

from fido2 import cbor
from fido2.webauthn import AuthenticatorData

# python-fido2 renamed its CBOR entry points across versions (dumps/loads
# <= 1.1, encode/decode >= 1.2); bind whichever exists.
_cbor_enc = getattr(cbor, "encode", None) or cbor.dumps
_cbor_dec = getattr(cbor, "decode", None) or cbor.loads

CHALLENGE_TTL_S = 60
ACTION_CHALLENGE_TTL_S = 30

# Yubico FIPS-series AAGUIDs; empty list = record-only (no pinning) so a
# firmware update cannot lock operators out.  Populate to enforce.
AAGUID_ALLOWLIST: list[str] = []


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class WebAuthnError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ── credential store (public material only, 0600) ──────────────────────────

@dataclass
class Credential:
    credential_id: str          # b64url
    username: str
    cose: str                   # b64url of the COSE CBOR key (public)
    sign_count: int = 0
    aaguid: str = ""
    label: str = ""
    created_at: float = field(default_factory=time.time)


class CredentialStore:
    """browser-credentials.json — PUBLIC keys + usernames only.  Not a
    secret store; its integrity protects login, so it is 0600 and every
    load/save is logged by the bridge."""

    def __init__(self, path: str):
        self.path = path
        self._creds: dict[str, Credential] = {}
        self.load()

    def load(self):
        self._creds.clear()
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            for item in raw.get("credentials", []):
                cred = Credential(**item)
                self._creds[cred.credential_id] = cred
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError, TypeError) as exc:
            raise WebAuthnError(
                "CREDSTORE",
                f"credential store {self.path!r} unreadable: {exc}") from exc

    def save(self):
        payload = {"version": 1,
                   "credentials": [c.__dict__ for c in self._creds.values()]}
        body = json.dumps(payload, indent=2, sort_keys=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(self.path, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(body)
        finally:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def usernames(self) -> list[str]:
        return sorted({c.username for c in self._creds.values()})

    def for_username(self, username: str) -> list[Credential]:
        return [c for c in self._creds.values() if c.username == username]

    def get(self, credential_id: str) -> Credential | None:
        return self._creds.get(credential_id)

    def put(self, cred: Credential):
        self._creds[cred.credential_id] = cred
        self.save()

    def update_sign_count(self, credential_id: str, count: int):
        cred = self._creds.get(credential_id)
        if cred is not None:
            cred.sign_count = count
            self.save()


# ── challenge registry (single-use, purpose-bound, TTL) ────────────────────

@dataclass
class Challenge:
    value: str                  # b64url, sent to the browser
    purpose: str                # login | action | enroll
    username: str
    session_id: str
    bound_command: str | None   # actions: exact canonical command
    expires: float
    used: bool = False


class ChallengeRegistry:
    def __init__(self, ttl: int = CHALLENGE_TTL_S):
        self.ttl = ttl
        self._by_value: dict[str, Challenge] = {}

    def issue(self, purpose: str, username: str, session_id: str,
              bound_command: str | None = None,
              ttl: float | None = None) -> Challenge:
        now = time.time()
        # GC expired entries (bounded registry)
        for value in [v for v, c in self._by_value.items() if c.expires < now]:
            del self._by_value[value]
        ch = Challenge(b64u(secrets.token_bytes(32)), purpose, username,
                       session_id, bound_command,
                       now + (ttl if ttl is not None else self.ttl))
        self._by_value[ch.value] = ch
        return ch

    def consume(self, value: str) -> Challenge:
        ch = self._by_value.get(value)
        if ch is None:
            raise WebAuthnError("BAD_CHALLENGE", "unknown or already-used challenge")
        if ch.used:
            raise WebAuthnError("BAD_CHALLENGE", "challenge already used")
        if time.time() > ch.expires:
            raise WebAuthnError("BAD_CHALLENGE", "challenge expired")
        ch.used = True
        return ch


# ── COSE key (de)serialisation, defensive across fido2 layouts ─────────────

def cose_to_cbor_bytes(cose_key) -> bytes:
    """Persist a parsed COSE key back to canonical CBOR bytes."""
    try:
        return _cbor_enc(cose_key)
    except Exception:
        pass
    # dict-style CoseKey (fido2 keeps COSE maps dict-backed)
    try:
        return _cbor_enc({k: cose_key[k] for k in cose_key.keys()})
    except Exception:
        pass
    # attribute fallback for EC2 keys
    alg = getattr(cose_key, "ALGORITHM", None)
    raise WebAuthnError("COSE", f"cannot serialise COSE key (alg={alg})")


def cose_from_cbor_bytes(data: bytes):
    """Parse stored COSE CBOR bytes back into a verify-capable key.

    We enroll ES256 only (pubKeyCredParams alg -7), so the EC2 COSE map
    is validated here and verified with the cryptography backend — this
    avoids depending on python-fido2's CoseKey constructors, whose
    signatures moved across 1.x releases (1.2.0's for_name(-7)(map)
    yields UnsupportedKey)."""
    parsed = _cbor_dec(data)
    if not isinstance(parsed, dict) or parsed.get(1) != 2 \
            or parsed.get(3) != -7 or parsed.get(-1) != 1 \
            or not isinstance(parsed.get(-2), (bytes, bytearray)) \
            or not isinstance(parsed.get(-3), (bytes, bytearray)):
        raise WebAuthnError("COSE", "stored key is not a P-256 ES256 COSE key")
    return parsed


def cose_verify(key, signature: bytes, message: bytes) -> bool:
    """Verify an ES256 signature over message with a parsed COSE key."""
    if hasattr(key, "verify"):
        try:
            key.verify(signature, message)
            return True
        except Exception:
            return False
    # Raw EC2 COSE map → cryptography fallback
    if isinstance(key, dict):
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.utils import (
                decode_dss_signature)
            x = int.from_bytes(key[-2], "big")
            y = int.from_bytes(key[-3], "big")
            pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            # WebAuthn ES256 signatures are already DER-encoded
            pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
    return False


# ── relying party ───────────────────────────────────────────────────────────

class RelyingParty:
    def __init__(self, port: int, rp_id: str = "localhost"):
        self.rp_id = rp_id
        self.rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        self.origins = {
            f"http://{rp_id}:{port}",
            f"http://{rp_id}:5173",      # vite dev server, deliberate
        }
        self.challenges = ChallengeRegistry()

    # — ceremonies ────────────────────────────────────────────────────

    def begin_login(self, store: CredentialStore, username: str,
                    session_id: str) -> dict:
        creds = store.for_username(username)
        if not creds:
            raise WebAuthnError("NO_CREDENTIAL",
                                f"no WebAuthn credential enrolled for {username!r}")
        ch = self.challenges.issue("login", username, session_id)
        return {
            "publicKey": {
                "challenge": ch.value,
                "rpId": self.rp_id,
                "allowCredentials": [
                    {"type": "public-key", "id": c.credential_id}
                    for c in creds
                ],
                "userVerification": "required",
                "timeout": CHALLENGE_TTL_S * 1000,
            }
        }

    def verify_login(self, store: CredentialStore, username: str,
                     session_id: str, credential: dict) -> Credential:
        """Verify a navigator.credentials.get() assertion for login.
        The credential MUST belong to the step-1 username."""
        ch = self._verify_assertion_common(store, "login", username,
                                           session_id, credential)
        cred = store.get(credential.get("id", ""))
        if cred is None or cred.username != username:
            raise WebAuthnError("WRONG_CREDENTIAL",
                                "assertion credential is not enrolled for this user")
        store.update_sign_count(cred.credential_id, ch.sign_count)
        return cred

    def begin_action(self, username: str, session_id: str,
                     canonical_command: str) -> dict:
        """Per-action UV challenge BOUND to the exact canonical command —
        the dialog's command and the dispatched command cannot diverge."""
        ch = self.challenges.issue("action", username, session_id,
                                   bound_command=canonical_command,
                                   ttl=ACTION_CHALLENGE_TTL_S)
        return {
            "publicKey": {
                "challenge": ch.value,
                "rpId": self.rp_id,
                "userVerification": "required",
                "timeout": ACTION_CHALLENGE_TTL_S * 1000,
            }
        }

    def verify_action(self, store: CredentialStore, username: str,
                      session_id: str, canonical_command: str,
                      credential: dict) -> None:
        ch = self._verify_assertion_common(store, "action", username,
                                           session_id, credential,
                                           bound_command=canonical_command)
        cred = store.get(credential.get("id", ""))
        if cred is None or cred.username != username:
            raise WebAuthnError("WRONG_CREDENTIAL",
                                "assertion credential is not enrolled for this user")
        store.update_sign_count(cred.credential_id, ch.sign_count)

    def begin_enroll(self, username: str, session_id: str) -> dict:
        ch = self.challenges.issue("enroll", username, session_id)
        return {
            "publicKey": {
                "challenge": ch.value,
                "rp": {"id": self.rp_id, "name": "QIHSE Browser"},
                "user": {"id": b64u(username.encode()),
                         "name": username,
                         "displayName": username},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "residentKey": "discouraged",
                    "userVerification": "required",
                },
                "attestation": "none",
                "timeout": CHALLENGE_TTL_S * 1000,
            }
        }

    def verify_enroll(self, username: str, session_id: str,
                      credential: dict) -> Credential:
        """Verify a navigator.credentials.create() result and return the
        (unsaved) Credential for the store."""
        ch = self.challenges.consume(credential.get("_challenge", ""))
        if ch.purpose != "enroll" or ch.username != username \
                or ch.session_id != session_id:
            raise WebAuthnError("BAD_CHALLENGE", "challenge/session mismatch")
        client_data = _parse_client_data(
            credential.get("response", {}).get("clientDataJSON", ""))
        _check_client_data(client_data, "webauthn.create", ch.value)
        _check_origin(self, client_data)
        att_obj_bytes = b64u_decode(
            credential.get("response", {}).get("attestationObject", ""))
        try:
            att_obj = _cbor_dec(att_obj_bytes)
            auth_data = AuthenticatorData(att_obj["authData"])
        except Exception as exc:
            raise WebAuthnError("BAD_ATTESTATION",
                                f"attestation object unparsable: {exc}") from exc
        self._check_auth_data(auth_data)
        attested = auth_data.credential_data
        if attested is None:
            raise WebAuthnError("BAD_ATTESTATION", "no attested credential data")
        aaguid = str(attested.aaguid)
        if AAGUID_ALLOWLIST and aaguid not in AAGUID_ALLOWLIST:
            raise WebAuthnError("BAD_AAGUID",
                                f"authenticator {aaguid} is not in the allow-list")
        cred_id = b64u(bytes(attested.credential_id))
        try:
            cose_bytes = cose_to_cbor_bytes(attested.public_key)
        except WebAuthnError as exc:
            raise WebAuthnError("BAD_KEY", exc.message) from exc
        return Credential(credential_id=cred_id, username=username,
                          cose=b64u(cose_bytes), sign_count=auth_data.counter,
                          aaguid=aaguid)

    # — shared assertion verification ─────────────────────────────────

    def _verify_assertion_common(self, store: CredentialStore, purpose: str,
                                 username: str, session_id: str,
                                 credential: dict,
                                 bound_command: str | None = None) -> Challenge:
        ch = self.challenges.consume(credential.get("_challenge", ""))
        if ch.purpose != purpose or ch.username != username \
                or ch.session_id != session_id:
            raise WebAuthnError("BAD_CHALLENGE", "challenge/session mismatch")
        if purpose == "action":
            if ch.bound_command != bound_command:
                raise WebAuthnError(
                    "COMMAND_MISMATCH",
                    "assertion is bound to a different command than the "
                    "one being dispatched")
        response = credential.get("response", {})
        client_raw = b64u_decode(response.get("clientDataJSON", ""))
        client_data = _parse_client_data(client_raw)
        _check_client_data(client_data, "webauthn.get", ch.value)
        _check_origin(self, client_data)
        auth_bytes = b64u_decode(response.get("authenticatorData", ""))
        try:
            auth_data = AuthenticatorData(auth_bytes)
        except Exception as exc:
            raise WebAuthnError("BAD_ASSERTION",
                                f"authenticator data unparsable: {exc}") from exc
        self._check_auth_data(auth_data)
        if auth_data.counter <= 0:
            raise WebAuthnError("BAD_SIGN_COUNT",
                                "authenticator reported sign_count 0 with UV")
        cred = store.get(credential.get("id", ""))
        if cred is not None and auth_data.counter <= cred.sign_count:
            raise WebAuthnError(
                "CLONE_SUSPECTED",
                f"sign_count did not increase ({auth_data.counter} <= "
                f"{cred.sign_count}); possible cloned authenticator")
        signature = b64u_decode(response.get("signature", ""))
        message = auth_bytes + hashlib.sha256(client_raw).digest()
        key = cose_from_cbor_bytes(b64u_decode(cred.cose)) if cred else None
        if key is None or not cose_verify(key, signature, message):
            raise WebAuthnError("BAD_SIGNATURE",
                                "assertion signature verification failed")
        ch.sign_count = auth_data.counter
        return ch

    def _check_auth_data(self, auth_data: AuthenticatorData):
        if auth_data.rp_id_hash != self.rp_id_hash:
            raise WebAuthnError("BAD_RP", "assertion RP ID hash mismatch")
        if not auth_data.is_user_present():
            raise WebAuthnError("NO_UP", "user presence flag not set")
        if not auth_data.is_user_verified():
            raise WebAuthnError("NO_UV", "user verification (PIN) flag not set")


def _parse_client_data(b64: str | bytes) -> dict:
    raw = b64 if isinstance(b64, (bytes, bytearray)) else b64u_decode(b64)
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise WebAuthnError("BAD_CLIENT_DATA",
                            f"clientDataJSON unparsable: {exc}") from exc
    if not isinstance(data, dict):
        raise WebAuthnError("BAD_CLIENT_DATA", "clientDataJSON is not an object")
    return data


def _check_client_data(data: dict, expected_type: str, challenge: str):
    if data.get("type") != expected_type:
        raise WebAuthnError("BAD_CLIENT_DATA",
                            f"client data type {data.get('type')!r} != {expected_type!r}")
    if data.get("challenge") != challenge:
        raise WebAuthnError("BAD_CHALLENGE", "client data challenge mismatch")
    if data.get("origin") is None:
        raise WebAuthnError("BAD_CLIENT_DATA", "client data has no origin")


def _check_origin(rp: "RelyingParty", data: dict):
    origin = data.get("origin")
    if origin not in rp.origins:
        raise WebAuthnError("BAD_ORIGIN",
                            f"origin {origin!r} is not an allowed bridge origin")
