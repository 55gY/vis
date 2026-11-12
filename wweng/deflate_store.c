/* deflate_store.c -- raw DEFLATE, STORED blocks only (RFC 1951 §3.2.4).
 * Stored block layout (all multi-byte fields little-endian):
 *   byte 0: bit0 = BFINAL, bits1-2 = BTYPE (00 = stored), bits3-7 = 0 pad
 *   bytes 1-2: LEN (chunk length, <= 65535)
 *   bytes 3-4: NLEN (one's complement of LEN)
 *   bytes 5..: the raw chunk bytes
 * Only the last chunk has BFINAL=1.
 */
#include "deflate_store.h"

int ww_deflate_store(const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t nblocks = (in_len + 65534) / 65535;
    size_t need = in_len + 5 * nblocks;
    size_t opos = 0, ipos = 0;

    if (nblocks == 0) nblocks = 1; /* empty input: one empty final block */
    if (need > out_cap) return -1;
    if (in_len == 0) {
        out[0] = 0x01; /* BFINAL=1, BTYPE=00 */
        out[1] = 0x00; out[2] = 0x00; /* LEN = 0 */
        out[3] = 0xff; out[4] = 0xff; /* NLEN = 0xffff */
        *out_len = 5;
        return 0;
    }

    while (ipos < in_len) {
        size_t chunk = in_len - ipos;
        int last = 0;
        if (chunk > 65535) chunk = 65535;
        else last = 1;
        out[opos++] = last ? 0x01 : 0x00;
        out[opos++] = (uint8_t)(chunk & 0xff);
        out[opos++] = (uint8_t)((chunk >> 8) & 0xff);
        out[opos++] = (uint8_t)(~chunk & 0xff);
        out[opos++] = (uint8_t)((~chunk >> 8) & 0xff);
        for (size_t i = 0; i < chunk; i++) out[opos++] = in[ipos++];
    }
    *out_len = opos;
    return 0;
}
