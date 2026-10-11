// WebAuthn ceremony helpers (YubiKey FIPS over FIDO2; RP ID is always
// "localhost" — the bridge binds loopback and SSH -L keeps the origin
// a secure context).

const b64uEncode = (buf) => {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const b64uDecode = (s) => {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const raw = atob(padded);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
};

const decodeOptions = (options) => ({
  publicKey: {
    challenge: b64uDecode(options.publicKey.challenge),
    rpId: options.publicKey.rpId,
    allowCredentials: (options.publicKey.allowCredentials || []).map((c) => ({
      type: c.type,
      id: b64uDecode(c.id),
    })),
    userVerification: options.publicKey.userVerification || 'required',
    timeout: options.publicKey.timeout || 60000,
  },
});

export async function getAssertion(options) {
  const credential = await navigator.credentials.get(decodeOptions(options));
  const r = credential.response;
  return {
    id: credential.id,
    rawId: b64uEncode(credential.rawId),
    response: {
      clientDataJSON: b64uEncode(r.clientDataJSON),
      authenticatorData: b64uEncode(r.authenticatorData),
      signature: b64uEncode(r.signature),
      userHandle: r.userHandle ? b64uEncode(r.userHandle) : null,
    },
  };
}

export async function createAttestation(options) {
  const o = options.publicKey;
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: b64uDecode(o.challenge),
      rp: o.rp,
      user: {
        ...o.user,
        id: b64uDecode(o.user.id),
      },
      pubKeyCredParams: o.pubKeyCredParams,
      authenticatorSelection: o.authenticatorSelection,
      attestation: o.attestation || 'none',
      timeout: o.timeout || 60000,
    },
  });
  const r = credential.response;
  return {
    id: credential.id,
    rawId: b64uEncode(credential.rawId),
    response: {
      clientDataJSON: b64uEncode(r.clientDataJSON),
      attestationObject: b64uEncode(r.attestationObject),
    },
  };
}
