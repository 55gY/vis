/* sbox.c -- S-box stream cipher, ported from decrypt_waterwall.py.
 * Verified against the Python reference (round-trip + known vectors).
 * Kernel-safe: no allocation, no library calls beyond memcpy.
 */
#include "sbox.h"
#include "sbox_tables.h"

static unsigned char WwAddend(unsigned long long counter)
{
    return (unsigned char)((counter & 0xffULL) | ((counter >> 8) & 0xffULL));
}

void WwSboxInit(WW_SBOX_CTX *ctx, int version, const unsigned char key[WW_SBOX_KEY_SIZE])
{
    const unsigned char *base = (version == 1) ? WW_SBOX_TABLE_A : WW_SBOX_TABLE_B;
    int i;
    for (i = 0; i < 256; i++) {
        ctx->sbox[i] = base[i];
    }
    /* 16 swaps: S[key[i]] <-> S[key[i+16]] for i in 0..15. */
    for (i = 0; i < 16; i++) {
        unsigned char a = key[i];
        unsigned char b = key[i + 16];
        unsigned char tmp = ctx->sbox[a];
        ctx->sbox[a] = ctx->sbox[b];
        ctx->sbox[b] = tmp;
    }
    /* Inverse table. */
    for (i = 0; i < 256; i++) {
        ctx->inv_sbox[ctx->sbox[i]] = (unsigned char)i;
    }
}

void WwSboxEncrypt(WW_SBOX_CTX *ctx, unsigned char *buf, size_t len, unsigned long long counter)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (unsigned char)(ctx->sbox[buf[i]] + WwAddend(counter));
        counter++;
    }
}

void WwSboxDecrypt(WW_SBOX_CTX *ctx, unsigned char *buf, size_t len, unsigned long long counter)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = ctx->inv_sbox[(unsigned char)(buf[i] - WwAddend(counter))];
        counter++;
    }
}
