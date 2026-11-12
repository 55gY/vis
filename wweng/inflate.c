/* inflate.c -- minimal raw DEFLATE (RFC 1951) decompressor.
 * Bit order is LSB-first within each byte; Huffman codes are canonical.
 * Window is 32 KiB. Only the output buffer is written; no malloc.
 *
 * Blocks: 0 = stored, 1 = fixed Huffman, 2 = dynamic Huffman.
 * Length codes 257..285 and distance codes 0..29 use the standard
 * base values and extra-bit counts from RFC 1951 section 3.2.5.
 */
#include "inflate.h"
#include <string.h>

#define WW_WIN 32768

typedef struct {
    const uint8_t *in;
    size_t in_len;
    size_t in_pos;      /* next byte to load */
    uint32_t bitbuf;    /* pending bits, LSB-first */
    int bitcnt;         /* number of valid bits in bitbuf */
} bitrd;

static int br_bits(bitrd *b, int n)
{
    uint32_t v = 0;
    while (b->bitcnt < n) {
        if (b->in_pos >= b->in_len) return -1;
        b->bitbuf |= (uint32_t)b->in[b->in_pos++] << b->bitcnt;
        b->bitcnt += 8;
    }
    v = b->bitbuf & ((n == 32) ? 0xffffffffu : ((1u << n) - 1u));
    b->bitbuf >>= n;
    b->bitcnt -= n;
    return (int)v;
}

static void br_align_byte(bitrd *b)
{
    b->bitbuf = 0;
    b->bitcnt = 0;
}

/* Canonical Huffman table: counts[1..15], symbols in code order. */
typedef struct {
    uint16_t counts[16];
    uint16_t symbols[288];
    int n_symbols;
} huff;

static int huff_build(huff *h, const uint8_t *lengths, int n)
{
    int i, len;
    uint16_t offs[16];
    memset(h->counts, 0, sizeof(h->counts));
    for (i = 0; i < n; i++) {
        if (lengths[i] > 15) return -1;
        h->counts[lengths[i]]++;
    }
    h->counts[0] = 0;
    offs[1] = 0;
    for (len = 1; len < 15; len++) offs[len + 1] = offs[len] + h->counts[len];
    for (i = 0; i < n; i++) {
        if (lengths[i] != 0) h->symbols[offs[lengths[i]]++] = (uint16_t)i;
    }
    h->n_symbols = n;
    return 0;
}

/* Decode one symbol. Returns symbol, or -1 on bad input. */
static int huff_decode(bitrd *b, const huff *h)
{
    int len, code = 0, first = 0, index = 0;
    for (len = 1; len <= 15; len++) {
        int bit = br_bits(b, 1);
        if (bit < 0) return -1;
        code |= bit;
        if (code - first < h->counts[len]) {
            return h->symbols[index + (code - first)];
        }
        index += h->counts[len];
        first = (first + h->counts[len]) << 1;
        code <<= 1;
    }
    return -1;
}

static const uint16_t len_base[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const uint8_t len_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const uint16_t dist_base[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577
};
static const uint8_t dist_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

static int inflate_block(bitrd *b, const huff *lit, const huff *dst,
                         uint8_t *out, size_t out_cap, size_t *out_len,
                         uint8_t *win, size_t *win_pos)
{
    for (;;) {
        int sym = huff_decode(b, lit);
        if (sym < 0) return -1;
        if (sym < 256) {
            if (*out_len >= out_cap) return 1;
            out[(*out_len)++] = (uint8_t)sym;
            win[*win_pos] = (uint8_t)sym;
            *win_pos = (*win_pos + 1) & (WW_WIN - 1);
        } else if (sym == 256) {
            return 0; /* end of block */
        } else {
            int li = sym - 257;
            int length, dist, extra;
            if (li < 0 || li >= 29) return -1;
            length = len_base[li];
            extra = len_extra[li];
            if (extra) {
                int e = br_bits(b, extra);
                if (e < 0) return -1;
                length += e;
            }
            sym = huff_decode(b, dst);
            if (sym < 0 || sym >= 30) return -1;
            dist = dist_base[sym];
            extra = dist_extra[sym];
            if (extra) {
                int e = br_bits(b, extra);
                if (e < 0) return -1;
                dist += e;
            }
            if (dist < 1 || dist > WW_WIN) return -1;
            if (*out_len + (size_t)length > out_cap) return 1;
            for (int i = 0; i < length; i++) {
                size_t src = (*win_pos + WW_WIN - (size_t)dist) & (WW_WIN - 1);
                uint8_t c = win[src];
                out[(*out_len)++] = c;
                win[*win_pos] = c;
                *win_pos = (*win_pos + 1) & (WW_WIN - 1);
            }
        }
    }
}

int ww_inflate(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    bitrd b;
    uint8_t win[WW_WIN];
    size_t win_pos = 0;
    size_t olen = 0;
    int final_block = 0;

    memset(&b, 0, sizeof(b));
    b.in = in;
    b.in_len = in_len;
    memset(win, 0, sizeof(win));
    *out_len = 0;

    while (!final_block) {
        int bfinal = br_bits(&b, 1);
        int btype = br_bits(&b, 2);
        if (bfinal < 0 || btype < 0) return -1;
        final_block = bfinal;

        if (btype == 0) {
            /* stored */
            uint16_t len, nlen;
            br_align_byte(&b);
            if (b.in_pos + 4 > b.in_len) return -1;
            len = (uint16_t)(b.in[b.in_pos] | (b.in[b.in_pos + 1] << 8));
            nlen = (uint16_t)(b.in[b.in_pos + 2] | (b.in[b.in_pos + 3] << 8));
            b.in_pos += 4;
            if ((uint16_t)~len != nlen) return -1;
            if (b.in_pos + len > b.in_len) return -1;
            if (olen + len > out_cap) return 1;
            memcpy(out + olen, b.in + b.in_pos, len);
            for (uint16_t i = 0; i < len; i++) {
                win[win_pos] = b.in[b.in_pos + i];
                win_pos = (win_pos + 1) & (WW_WIN - 1);
            }
            olen += len;
            b.in_pos += len;
        } else if (btype == 1) {
            /* fixed Huffman */
            uint8_t litlen[288], distlen[32];
            huff lit, dst;
            int i;
            for (i = 0; i < 144; i++) litlen[i] = 8;
            for (; i < 256; i++) litlen[i] = 9;
            for (; i < 280; i++) litlen[i] = 7;
            for (; i < 288; i++) litlen[i] = 8;
            for (i = 0; i < 32; i++) distlen[i] = 5;
            if (huff_build(&lit, litlen, 288) < 0) return -1;
            if (huff_build(&dst, distlen, 32) < 0) return -1;
            int r = inflate_block(&b, &lit, &dst, out, out_cap, &olen, win, &win_pos);
            if (r != 0) return r;
        } else if (btype == 2) {
            /* dynamic Huffman */
            int hlit = br_bits(&b, 5);
            int hdist = br_bits(&b, 5);
            int hclen = br_bits(&b, 4);
            static const uint8_t order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
            uint8_t clen[19];
            uint8_t litlen[288], distlen[32];
            huff cl, lit, dst;
            int i;
            if (hlit < 0 || hdist < 0 || hclen < 0) return -1;
            hlit += 257; hdist += 1; hclen += 4;
            memset(clen, 0, sizeof(clen));
            for (i = 0; i < hclen; i++) {
                int v = br_bits(&b, 3);
                if (v < 0) return -1;
                clen[order[i]] = (uint8_t)v;
            }
            if (huff_build(&cl, clen, 19) < 0) return -1;
            {
                int total = hlit + hdist;
                int n = 0;
                while (n < total) {
                    int sym = huff_decode(&b, &cl);
                    if (sym < 0) return -1;
                    if (sym < 16) {
                        if (n >= total) return -1;
                        if (n < hlit) litlen[n] = (uint8_t)sym;
                        else distlen[n - hlit] = (uint8_t)sym;
                        n++;
                    } else if (sym == 16) {
                        int rep = br_bits(&b, 2);
                        int prev;
                        if (rep < 0 || n == 0) return -1;
                        rep += 3;
                        prev = (n < hlit) ? litlen[n - 1] : distlen[n - hlit - 1];
                        while (rep-- > 0) {
                            if (n >= total) return -1;
                            if (n < hlit) litlen[n] = (uint8_t)prev;
                            else distlen[n - hlit] = (uint8_t)prev;
                            n++;
                        }
                    } else if (sym == 17) {
                        int rep = br_bits(&b, 3);
                        if (rep < 0) return -1;
                        rep += 3;
                        while (rep-- > 0) {
                            if (n >= total) return -1;
                            if (n < hlit) litlen[n] = 0;
                            else distlen[n - hlit] = 0;
                            n++;
                        }
                    } else if (sym == 18) {
                        int rep = br_bits(&b, 7);
                        if (rep < 0) return -1;
                        rep += 11;
                        while (rep-- > 0) {
                            if (n >= total) return -1;
                            if (n < hlit) litlen[n] = 0;
                            else distlen[n - hlit] = 0;
                            n++;
                        }
                    } else {
                        return -1;
                    }
                }
            }
            if (huff_build(&lit, litlen, hlit) < 0) return -1;
            if (huff_build(&dst, distlen, hdist) < 0) return -1;
            int r = inflate_block(&b, &lit, &dst, out, out_cap, &olen, win, &win_pos);
            if (r != 0) return r;
        } else {
            return -1; /* BTYPE 3, reserved */
        }
    }

    *out_len = olen;
    return 0;
}
