package com.kp14.synthetic.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.spec.SecretKeySpec;

/** Negative control 2: SecretKeySpec built from runtime-derived bytes
 *  (char-array transform), no constant-load dataflow neighborhood feeding
 *  the array argument. Expect NO DEX.KEY.HARDCODED finding. */
public class DerivedKeyCrypto {
    public SecretKeySpec derivedKey(char[] material) {
        byte[] bytes = new byte[material.length];
        for (int i = 0; i < material.length; i++) {
            bytes[i] = (byte) ((material[i] ^ 0x5a) & 0xff);
        }
        return new SecretKeySpec(bytes, "AES");
    }

    public SecretKeySpec fromString(String seed, String salt) {
        return new SecretKeySpec((seed + salt).getBytes(StandardCharsets.UTF_8), "AES");
    }
}
