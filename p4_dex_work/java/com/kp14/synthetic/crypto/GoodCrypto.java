package com.kp14.synthetic.crypto;

import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

/** Negative control 1: SecureRandom only. SecureRandom dispatches through
 *  Random's method table (nextInt is inherited), so a naive
 *  "Ljava/util/Random;-> method ref" matcher would false-positive here —
 *  the RNG detector must count constructions only. Expect NO findings. */
public class GoodCrypto {
    private final SecureRandom rng = new SecureRandom();

    public int nextNonce() {
        return rng.nextInt();
    }

    public int nextBounded(int bound) {
        return rng.nextInt(bound);
    }
}
