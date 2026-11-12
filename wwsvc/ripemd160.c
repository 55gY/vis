/* RIPEMD-160 -- standard implementation (from the public spec).
 * Self-test vectors: "" -> 9c1185a5c5e9fc54612808977ee8f548b2258d31
 *                    "abc" -> 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
 */
#include <stdint.h>
#include <string.h>

static uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static const uint32_t R[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};
static const uint32_t RP[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};
static const uint32_t S[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};
static const uint32_t SP[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};
static const uint32_t K[5] = { 0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xa953fd4eu };
static const uint32_t KP[5] = { 0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x7a6d76e9u, 0x00000000u };

static uint32_t f(int j, uint32_t x, uint32_t y, uint32_t z)
{
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

static void ripemd160_block(const uint8_t *blk, uint32_t h[5])
{
    uint32_t X[16];
    for (int i = 0; i < 16; i++)
        X[i] = (uint32_t)blk[i * 4] | ((uint32_t)blk[i * 4 + 1] << 8) |
               ((uint32_t)blk[i * 4 + 2] << 16) | ((uint32_t)blk[i * 4 + 3] << 24);
    uint32_t A = h[0], B = h[1], C = h[2], D = h[3], E = h[4];
    uint32_t Ap = h[0], Bp = h[1], Cp = h[2], Dp = h[3], Ep = h[4];
    for (int j = 0; j < 80; j++) {
        uint32_t T = rol32(A + f(j, B, C, D) + X[R[j]] + K[j / 16], S[j]) + E;
        A = E; E = D; D = rol32(C, 10); C = B; B = T;
        int jr = 79 - j;
        uint32_t Tp = rol32(Ap + f(jr, Bp, Cp, Dp) + X[RP[j]] + KP[j / 16], SP[j]) + Ep;
        Ap = Ep; Ep = Dp; Dp = rol32(Cp, 10); Cp = Bp; Bp = Tp;
    }
    uint32_t T = h[1] + C + Dp;
    h[1] = h[2] + D + Ep;
    h[2] = h[3] + E + Ap;
    h[3] = h[4] + A + Bp;
    h[4] = h[0] + B + Cp;
    h[0] = T;
}

void ripemd160(const uint8_t *msg, size_t len, uint8_t out[20])
{
    uint32_t h[5] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u };
    uint8_t blk[64];
    size_t off = 0;
    while (len - off >= 64) {
        ripemd160_block(msg + off, h);
        off += 64;
    }
    size_t rem = len - off;
    memset(blk, 0, 64);
    memcpy(blk, msg + off, rem);
    blk[rem] = 0x80;
    if (rem >= 56) {
        ripemd160_block(blk, h);
        memset(blk, 0, 64);
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) blk[56 + i] = (uint8_t)(bits >> (8 * i));
    ripemd160_block(blk, h);
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(h[i] & 0xff);
        out[i * 4 + 1] = (uint8_t)((h[i] >> 8) & 0xff);
        out[i * 4 + 2] = (uint8_t)((h[i] >> 16) & 0xff);
        out[i * 4 + 3] = (uint8_t)((h[i] >> 24) & 0xff);
    }
}
