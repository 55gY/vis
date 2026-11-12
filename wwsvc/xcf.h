/* xcf.h -- WaterWall .xcf config reader.
 * .xcf = raw DEFLATE stream (RFC 1951) of GBK text:
 *   //TEXT... header line
 *   N, <section>
 *   \tN.N, <key>, <value>
 * Only ASCII section/key/value lookups are needed (USB policy), so the
 * text is handled as bytes; GBK values are passed through untouched.
 * Returns 1 and copies the value (NUL-terminated) when found, else 0.
 */
#ifndef WW_XCF_H
#define WW_XCF_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *text;      /* decompressed text (NUL-terminated, owned) */
    size_t text_len;
} xcf_t;

/* Load and decompress a .xcf file. Returns 0 on success, <0 on failure. */
int xcf_load(const char *path, xcf_t *x);
void xcf_free(xcf_t *x);

/* Case-insensitive section/key lookup. Value is trimmed. */
int xcf_get(const xcf_t *x, const char *section, const char *key,
            char *out, size_t out_cap);

/* Set EVERY key in `section` to `new_value` (raw bytes, new_value_len).
 * Rebuilds the text in place (line endings and key prefixes preserved).
 * Returns the number of keys changed, or -1 on allocation failure.
 * Used by the policy takeover: move all User entries to the main policy. */
int xcf_set_all_in_section(xcf_t *x, const char *section,
                           const uint8_t *new_value, size_t new_value_len);

#endif
