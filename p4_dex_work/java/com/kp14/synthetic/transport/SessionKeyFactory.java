package com.kp14.synthetic.transport;

import java.util.Random;

/** Synthetic weak-RNG bug: Random used for a session token in a
 *  transport-named package (expect DEX.RNG.WEAK severity HIGH). */
public class SessionKeyFactory {
    public String nextSessionToken() {
        Random rng = new Random();
        return Long.toHexString(rng.nextLong());
    }
}
