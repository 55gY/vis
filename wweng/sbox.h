/* sbox.h -- S-box stream cipher (ported from decrypt_waterwall.py).
 * Matches the old client's cipher byte-for-byte so files stay compatible.
 *
 * Cipher: cipher[i] = S[plain[i]] + addend(counter); counter++ per byte.
 * Decrypt: plain[i] = invS[(cipher[i] - addend(counter)) & 0xff].
 * addend(counter) = (counter & 0xff) | ((counter >> 8) & 0xff).
 * The keyed S-box is built by copying base table A (version 1) or B
 * (version 2), then 16 swaps S[key[i]] <-> S[key[i+16]] for i in 0..15.
 * The counter for a byte is its logical file offset.
 *
 * Kernel-safe: no allocation, no floating point, no library calls.
 * The caller owns the WW_SBOX_CTX (typically inside a stream context).
 */
#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

#define WW_SBOX_KEY_SIZE 32

typedef struct _WW_SBOX_CTX {
    unsigned char sbox[256];
    unsigned char inv_sbox[256];
} WW_SBOX_CTX;

/* Build the keyed S-box + inverse. version: 1 -> table A, 2 -> table B.
 * key is 32 bytes. */
void WwSboxInit(WW_SBOX_CTX *ctx, int version, const unsigned char key[WW_SBOX_KEY_SIZE]);

/* Encrypt/decrypt `len` bytes in place. `counter` is the starting counter
 * (the logical file offset of buf[0]); it advances by 1 per byte.
 * Encrypt and decrypt are the same function shape; use the matching one. */
void WwSboxEncrypt(WW_SBOX_CTX *ctx, unsigned char *buf, size_t len, unsigned long long counter);
void WwSboxDecrypt(WW_SBOX_CTX *ctx, unsigned char *buf, size_t len, unsigned long long counter);
