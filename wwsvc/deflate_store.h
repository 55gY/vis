/* deflate_store.h -- raw DEFLATE encoder using STORED blocks only (RFC 1951).
 * A stored block is just the raw bytes with a 5-byte header, so this needs
 * no Huffman coding at all, yet produces a fully valid raw DEFLATE stream
 * that any inflater (including the vendor .xcf reader) accepts.
 * Used to write back a modified wwkrn.xcf after a policy change.
 */
#ifndef WW_DEFLATE_STORE_H
#define WW_DEFLATE_STORE_H
#include <stddef.h>
#include <stdint.h>

/* Compress `in` (in_len bytes) into `out` (capacity out_cap).
 * On success returns 0 and sets *out_len. Returns -1 if out_cap is too
 * small. Output size is in_len + 5 * ceil(in_len / 65535). */
int ww_deflate_store(const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

#endif
