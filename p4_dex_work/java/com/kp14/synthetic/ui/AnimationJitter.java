package com.kp14.synthetic.ui;

import java.util.Random;

/** Synthetic weak-RNG usage in a UI-named package: same construction
 *  pattern but low-stakes context (expect DEX.RNG.WEAK severity MEDIUM). */
public class AnimationJitter {
    private final Random rng = new Random();

    public int jitterPx(int base) {
        return base + rng.nextInt(4);
    }
}
