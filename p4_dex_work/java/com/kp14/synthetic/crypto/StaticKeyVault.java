package com.kp14.synthetic.crypto;

import javax.crypto.spec.SecretKeySpec;

/** Synthetic hardcoded key: SecretKeySpec fed directly from a byte[]
 *  literal (expect DEX.KEY.HARDCODED, proximity heuristic). */
public class StaticKeyVault {
    public byte[] aesKeyBytes() {
        return new byte[]{
            0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
            (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c
        };
    }

    public SecretKeySpec keySpec() {
        return new SecretKeySpec(aesKeyBytes(), "AES");
    }
}
