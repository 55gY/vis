/* xcf.c -- WaterWall .xcf config reader (raw DEFLATE + GBK text). */
#include "xcf.h"
#include "inflate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define XCF_MAX_RAW   (4u * 1024u * 1024u)   /* compressed file cap */
#define XCF_MAX_TEXT  (4u * 1024u * 1024u)   /* decompressed text cap */

int xcf_load(const char *path, xcf_t *x)
{
    FILE *f = fopen(path, "rb");
    uint8_t *raw = NULL;
    uint8_t *text = NULL;
    size_t raw_len = 0, text_len = 0;
    int rc = -1;

    memset(x, 0, sizeof(*x));
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || (size_t)sz > XCF_MAX_RAW) { fclose(f); return -1; }
    raw = (uint8_t *)malloc((size_t)sz);
    if (!raw) { fclose(f); return -1; }
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz) { free(raw); fclose(f); return -1; }
    fclose(f);
    raw_len = (size_t)sz;

    text = (uint8_t *)malloc(XCF_MAX_TEXT + 1);
    if (!text) { free(raw); return -1; }
    rc = ww_inflate(raw, raw_len, text, XCF_MAX_TEXT, &text_len);
    free(raw);
    if (rc != 0) { free(text); return -2; }
    text[text_len] = 0;
    x->text = text;
    x->text_len = text_len;
    return 0;
}

void xcf_free(xcf_t *x)
{
    if (x->text) free(x->text);
    memset(x, 0, sizeof(*x));
}

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

static void trim_copy(const char *begin, const char *end, char *out, size_t out_cap)
{
    while (begin < end && (*begin == ' ' || *begin == '\t')) begin++;
    while (end > begin && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) end--;
    size_t n = (size_t)(end - begin);
    if (n >= out_cap) n = out_cap - 1;
    memcpy(out, begin, n);
    out[n] = 0;
}

static int ci_equal(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

int xcf_get(const xcf_t *x, const char *section, const char *key,
            char *out, size_t out_cap)
{
    char cur_section[128] = { 0 };
    const char *p = (const char *)x->text;
    const char *end = p + x->text_len;

    while (p < end) {
        const char *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;
        const char *line = skip_ws(p);
        if (line < line_end && line[0] == '/' && line + 1 < line_end && line[1] == '/') {
            /* comment line, skip */
        } else if (line < line_end && isdigit((unsigned char)line[0])) {
            /* find commas */
            const char *c1 = NULL, *c2 = NULL;
            for (const char *q = line; q < line_end; q++) {
                if (*q == ',') { if (!c1) c1 = q; else { c2 = q; break; } }
            }
            if (c1 && !c2) {
                /* section header: N, <name> */
                trim_copy(c1 + 1, line_end, cur_section, sizeof(cur_section));
            } else if (c1 && c2) {
                /* key line: N.N, <key>, <value...> -- first field must contain '.' */
                int dotted = 0;
                for (const char *q = line; q < c1; q++) if (*q == '.') { dotted = 1; break; }
                if (dotted) {
                    char k[128];
                    trim_copy(c1 + 1, c2, k, sizeof(k));
                    if (ci_equal(cur_section, section) && ci_equal(k, key)) {
                        trim_copy(c2 + 1, line_end, out, out_cap);
                        return 1;
                    }
                } else {
                    /* N, <name>, ... with extra commas: treat as section header */
                    trim_copy(c1 + 1, line_end, cur_section, sizeof(cur_section));
                }
            }
        }
        p = (line_end < end) ? line_end + 1 : end;
    }
    return 0;
}

int xcf_set_all_in_section(xcf_t *x, const char *section,
                           const uint8_t *new_value, size_t new_value_len)
{
    char cur_section[128] = { 0 };
    const char *p = (const char *)x->text;
    const char *end = p + x->text_len;
    int changed = 0;
    size_t new_len = 0;
    uint8_t *nb = NULL;
    size_t npos = 0;

    /* pass 1: count target keys and compute the new total length */
    while (p < end) {
        const char *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;
        const char *line = skip_ws(p);
        size_t line_len = (size_t)((line_end < end ? line_end + 1 : end) - p);
        new_len += line_len;
        if (line < line_end && line[0] == '/' && line + 1 < line_end && line[1] == '/') {
            /* comment */
        } else if (line < line_end && isdigit((unsigned char)line[0])) {
            const char *c1 = NULL, *c2 = NULL;
            for (const char *q = line; q < line_end; q++) {
                if (*q == ',') { if (!c1) c1 = q; else { c2 = q; break; } }
            }
            if (c1 && !c2) {
                trim_copy(c1 + 1, line_end, cur_section, sizeof(cur_section));
            } else if (c1 && c2) {
                int dotted = 0;
                for (const char *q = line; q < c1; q++) if (*q == '.') { dotted = 1; break; }
                if (dotted) {
                    if (ci_equal(cur_section, section)) {
                        /* value span: after 2nd comma (skip spaces) to line end (trim \r) */
                        const char *vs = c2 + 1;
                        while (vs < line_end && (*vs == ' ' || *vs == '\t')) vs++;
                        const char *ve = line_end;
                        while (ve > vs && (ve[-1] == '\r' || ve[-1] == ' ' || ve[-1] == '\t')) ve--;
                        changed++;
                        {
                            /* signed-safe delta: new value may be shorter */
                            size_t old_vlen = (size_t)(ve - vs);
                            if (new_value_len >= old_vlen)
                                new_len += new_value_len - old_vlen;
                            else
                                new_len -= old_vlen - new_value_len;
                        }
                    }
                } else {
                    trim_copy(c1 + 1, line_end, cur_section, sizeof(cur_section));
                }
            }
        }
        p = (line_end < end) ? line_end + 1 : end;
    }
    if (changed == 0) return 0;

    nb = (uint8_t *)malloc(new_len + 1);
    if (!nb) return -1;

    /* pass 2: rebuild */
    cur_section[0] = 0;
    p = (const char *)x->text;
    while (p < end) {
        const char *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;
        const char *line = skip_ws(p);
        const char *next = (line_end < end) ? line_end + 1 : end;
        int is_target = 0;
        const char *vs = NULL, *ve = NULL;
        if (line < line_end && line[0] == '/' && line + 1 < line_end && line[1] == '/') {
            /* comment */
        } else if (line < line_end && isdigit((unsigned char)line[0])) {
            const char *c1 = NULL, *c2 = NULL;
            for (const char *q = line; q < line_end; q++) {
                if (*q == ',') { if (!c1) c1 = q; else { c2 = q; break; } }
            }
            if (c1 && !c2) {
                trim_copy(c1 + 1, line_end, cur_section, sizeof(cur_section));
            } else if (c1 && c2) {
                int dotted = 0;
                for (const char *q = line; q < c1; q++) if (*q == '.') { dotted = 1; break; }
                if (dotted) {
                    if (ci_equal(cur_section, section)) {
                        is_target = 1;
                        vs = c2 + 1;
                        while (vs < line_end && (*vs == ' ' || *vs == '\t')) vs++;
                        ve = line_end;
                        while (ve > vs && (ve[-1] == '\r' || ve[-1] == ' ' || ve[-1] == '\t')) ve--;
                    }
                } else {
                    trim_copy(c1 + 1, line_end, cur_section, sizeof(cur_section));
                }
            }
        }
        if (is_target) {
            /* prefix up to value start, new value, then original line ending */
            size_t pre = (size_t)(vs - p);
            memcpy(nb + npos, p, pre); npos += pre;
            memcpy(nb + npos, new_value, new_value_len); npos += new_value_len;
            /* line ending: from ve to next (covers \r\n or \n) */
            size_t tail = (size_t)(next - ve);
            memcpy(nb + npos, ve, tail); npos += tail;
        } else {
            size_t n = (size_t)(next - p);
            memcpy(nb + npos, p, n); npos += n;
        }
        p = next;
    }
    nb[npos] = 0;
    free(x->text);
    x->text = nb;
    x->text_len = npos;
    return changed;
}
