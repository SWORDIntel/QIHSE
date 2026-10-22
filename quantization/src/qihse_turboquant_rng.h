/* Internal, independently implemented RFC 8439 section 2.3 block function.
 * Only a deterministic numerical generator here, NOT an encryption API.
 * Public 64-bit seeds do not supply cryptographic key entropy. */
#ifndef QIHSE_TURBOQUANT_RNG_H
#define QIHSE_TURBOQUANT_RNG_H
#include <stdint.h>

static inline uint32_t tq_rotate_left(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32-n));
}
static inline void tq_quarter_round(uint32_t *x, unsigned a, unsigned b,
                                    unsigned c, unsigned d) {
    x[a] += x[b]; x[d] = tq_rotate_left(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = tq_rotate_left(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = tq_rotate_left(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = tq_rotate_left(x[b] ^ x[c], 7);
}
/* state = four constants, eight key words, counter, three nonce words.
 * Output words are serialized low-byte first by the numerical RNG consumer. */
static inline void tq_chacha20_block(const uint32_t state[16], uint32_t out[16]) {
    unsigned i, round;
    for (i = 0; i < 16; ++i) out[i] = state[i];
    for (round = 0; round < 10; ++round) {
        for (i = 0; i < 4; ++i) tq_quarter_round(out, i, i+4, i+8, i+12);
        for (i = 0; i < 4; ++i)
            tq_quarter_round(out, i, 4+(i+1)%4, 8+(i+2)%4, 12+(i+3)%4);
    }
    for (i = 0; i < 16; ++i) out[i] += state[i];
}
#endif
