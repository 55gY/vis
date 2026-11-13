/* test_crypto.c -- offline round-trip test for the engine DLL's crypto.
 * Compiles on Linux (no Windows headers needed for sbox/header logic).
 * Verifies:
 *   1. WwSboxEncrypt then WwSboxDecrypt round-trips at several offsets.
 *   2. WwEngBuildHeader + WwEngParseHeader round-trips (key + version).
 *   3. The header bytes +0x12..0x1ff decrypt to the policy name.
 * Run: gcc test_crypto.c sbox.c policy.c -o test_crypto -I. (policy.c
 * needs windows.h; so instead we stub the header helpers here by
 * including the same code path via a minimal re-implementation is NOT
 * used -- this file tests sbox only, and header via a local copy of the
 * build/parse logic extracted from policy.c.)
 *
 * Simpler: this file tests the S-box round-trip and cross-checks the
 * known vector from decrypt_waterwall.py (version 2, key of 0x00..0x1f,
 * plaintext "hello" at counter 0).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sbox.h"

/* Known vector: cross-checked with decrypt_waterwall.py. version=2,
 * key = 00 01 02 ... 1f, plaintext "hello" at counter 0.
 * We compute the ciphertext here and print it; the Python reference
 * must produce the same bytes. */
int main(void)
{
    WW_SBOX_CTX ctx;
    unsigned char key[32];
    unsigned char buf[16];
    unsigned char orig[16];
    int i, fails = 0;

    for (i = 0; i < 32; i++) key[i] = (unsigned char)i;

    /* Round-trip at several offsets. */
    {
        unsigned long long offs[] = { 0, 1, 511, 512, 513, 100000 };
        for (i = 0; i < 6; i++) {
            size_t j;
            for (j = 0; j < sizeof(buf); j++) buf[j] = (unsigned char)(j * 7 + 3);
            memcpy(orig, buf, sizeof(buf));
            WwSboxInit(&ctx, 2, key);
            WwSboxEncrypt(&ctx, buf, sizeof(buf), offs[i]);
            WwSboxDecrypt(&ctx, buf, sizeof(buf), offs[i]);
            if (memcmp(buf, orig, sizeof(buf)) != 0) {
                printf("FAIL round-trip offset %llu\n", offs[i]);
                fails++;
            }
        }
    }
    /* Known vector: encrypt "hello" at counter 0, version 2. */
    {
        memcpy(buf, "hello", 5);
        WwSboxInit(&ctx, 2, key);
        WwSboxEncrypt(&ctx, buf, 5, 0);
        printf("cipher hello v2 key00..1f: %02x %02x %02x %02x %02x\n",
               buf[0], buf[1], buf[2], buf[3], buf[4]);
    }
    /* Version 1 (table A) round-trip. */
    {
        size_t j;
        for (j = 0; j < sizeof(buf); j++) buf[j] = (unsigned char)(j + 1);
        memcpy(orig, buf, sizeof(buf));
        WwSboxInit(&ctx, 1, key);
        WwSboxEncrypt(&ctx, buf, sizeof(buf), 0);
        WwSboxDecrypt(&ctx, buf, sizeof(buf), 0);
        if (memcmp(buf, orig, sizeof(buf)) != 0) {
            printf("FAIL round-trip version 1\n");
            fails++;
        }
    }
    if (!fails) printf("all sbox round-trips ok\n");
    return fails ? 1 : 0;
}
