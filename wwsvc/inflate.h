/* inflate.h -- minimal raw DEFLATE (RFC 1951) decompressor.
 * No dependencies, no allocation beyond the caller's output buffer.
 * Used to read WaterWall .xcf files (raw DEFLATE stream, no zlib header).
 * Returns 0 on success, <0 on malformed input, >0 if output buffer too small.
 */
#ifndef WW_INFLATE_H
#define WW_INFLATE_H
#include <stddef.h>
#include <stdint.h>

int ww_inflate(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len);

#endif
