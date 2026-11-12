/* policy_build.c -- build a WWFLT_POLICY from a loaded .xcf.
 * Parses the .xcf text directly (same line format as xcf.c):
 *   section header: N, <name>
 *   key line:       N.N, <key>, <value>
 *   comment:        //...
 * Section/key names are case-insensitive. Keys of interest:
 *   Encrypt <exe> = Write | Read
 *   File    <exe> = <ext>|<ext>|...
 * Merge: Kernel (main) first, then the active group overlays it.
 * The active group is the first value in the User section (all User
 * entries point at the same group in practice); if the User section is
 * empty, the Kernel policy is used as-is.
 */
#include "policy_build.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define PB_MAX_LINE 1024

static int ci_equal_n(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
        if (a[i] == 0) return b[i] == 0;
    }
    return b[n] == 0;
}

static int ci_startswith(const char *s, const char *prefix)
{
    while (*prefix) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
        s++; prefix++;
    }
    return 1;
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

static void to_lower_ascii(char *s)
{
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/* Convert an ASCII (or GBK) byte string to WCHAR. ASCII bytes map 1:1.
 * For the group name (GBK), use MultiByteToWideChar(CP_GBK). Returns the
 * number of WCHARs written (excluding NUL). */
static int ascii_to_wide(const char *src, WCHAR *dst, size_t dst_chars)
{
    size_t i;
    for (i = 0; i < dst_chars - 1 && src[i]; i++) dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
    return (int)i;
}

/* One collected process rule (ASCII form, before conversion to WCHAR). */
typedef struct {
    char exe[64];        /* lowercase, e.g. "notepad.exe" */
    ULONG mode;          /* WWFLT_ENCRYPT_* */
    char ext_list[512];  /* e.g. "txt|pdf" (may be empty) */
    int has_ext;
} pb_rule_t;

typedef struct {
    pb_rule_t rules[WWFLT_MAX_PROCESSES];
    int count;
} pb_table_t;

static pb_rule_t *pb_find(pb_table_t *t, const char *exe)
{
    int i;
    for (i = 0; i < t->count; i++) {
        if (strcmp(t->rules[i].exe, exe) == 0) return &t->rules[i];
    }
    return NULL;
}

static pb_rule_t *pb_get_or_add(pb_table_t *t, const char *exe)
{
    pb_rule_t *r = pb_find(t, exe);
    if (r) return r;
    if (t->count >= WWFLT_MAX_PROCESSES) return NULL;
    r = &t->rules[t->count++];
    memset(r, 0, sizeof(*r));
    strncpy(r->exe, exe, sizeof(r->exe) - 1);
    r->mode = WWFLT_ENCRYPT_NONE;
    r->has_ext = 0;
    return r;
}

/* Walk every key/value in `section` of the .xcf text. For each key line,
 * call fn(key, value, ctx). The key and value are trimmed copies. */
typedef void (*pb_key_fn)(const char *key, const char *value, void *ctx);

static void pb_walk_section(const xcf_t *x, const char *section, pb_key_fn fn, void *ctx)
{
    char cur_section[128] = { 0 };
    const char *p = (const char *)x->text;
    const char *end = p + x->text_len;
    char keybuf[256], valbuf[1024];

    while (p < end) {
        const char *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;
        const char *line = p;
        while (line < line_end && (*line == ' ' || *line == '\t' || *line == '\r')) line++;
        if (line < line_end && line[0] == '/' && line + 1 < line_end && line[1] == '/') {
            /* comment */
        } else if (line < line_end && isdigit((unsigned char)line[0])) {
            const char *c1 = NULL, *c2 = NULL;
            const char *q;
            for (q = line; q < line_end; q++) {
                if (*q == ',') { if (!c1) c1 = q; else { c2 = q; break; } }
            }
            if (c1 && !c2) {
                trim_copy(c1 + 1, line_end, cur_section, sizeof(cur_section));
            } else if (c1 && c2) {
                int dotted = 0;
                for (q = line; q < c1; q++) if (*q == '.') { dotted = 1; break; }
                if (dotted) {
                    if (ci_equal_n(cur_section, section, strlen(section)) && strlen(cur_section) == strlen(section)) {
                        trim_copy(c1 + 1, c2, keybuf, sizeof(keybuf));
                        trim_copy(c2 + 1, line_end, valbuf, sizeof(valbuf));
                        fn(keybuf, valbuf, ctx);
                    }
                } else {
                    trim_copy(c1 + 1, line_end, cur_section, sizeof(cur_section));
                }
            }
        }
        p = (line_end < end) ? line_end + 1 : end;
    }
}

/* Collect Encrypt/File rules from one section into the table. */
typedef struct { pb_table_t *t; } pb_collect_ctx;

static void pb_collect_key(const char *key, const char *value, void *ctx)
{
    pb_collect_ctx *c = (pb_collect_ctx *)ctx;
    char exe[64];
    pb_rule_t *r;
    if (ci_startswith(key, "Encrypt ")) {
        const char *e = key + 8;
        while (*e == ' ' || *e == '\t') e++;
        strncpy(exe, e, sizeof(exe) - 1); exe[sizeof(exe) - 1] = 0;
        to_lower_ascii(exe);
        if (!exe[0]) return;
        r = pb_get_or_add(c->t, exe);
        if (!r) return;
        if (ci_equal_n(value, "Write", 5) && value[5] == 0) r->mode = WWFLT_ENCRYPT_WRITE;
        else if (ci_equal_n(value, "Read", 4) && value[4] == 0) r->mode = WWFLT_ENCRYPT_READ;
        else r->mode = WWFLT_ENCRYPT_NONE;
    } else if (ci_startswith(key, "File ")) {
        const char *e = key + 5;
        while (*e == ' ' || *e == '\t') e++;
        strncpy(exe, e, sizeof(exe) - 1); exe[sizeof(exe) - 1] = 0;
        to_lower_ascii(exe);
        if (!exe[0]) return;
        r = pb_get_or_add(c->t, exe);
        if (!r) return;
        /* Copy the extension list, stripping per-extension qualifiers
         * ("=main" / "=read") so the driver can match the bare extension.
         * E.g. "dwg=main|dwf|tmp=read" -> "dwg|dwf|tmp".
         * Note: "=read" ideally means "decrypt-only for this extension",
         * but Phase 1 treats it as a normal controlled extension (the
         * process Encrypt mode decides); over-encryption of a "=read"
         * extension (usually tmp/config) is harmless. */
        {
            const char *s = value;
            char *d = r->ext_list;
            size_t cap = sizeof(r->ext_list) - 1;
            while (*s && (size_t)(d - r->ext_list) < cap) {
                if (*s == '=') {
                    /* skip to the next '|' or end */
                    while (*s && *s != '|') s++;
                } else {
                    *d++ = *s++;
                }
            }
            *d = 0;
        }
        r->has_ext = 1;
    }
    /* dir/wild/include path rules: not parsed in Phase 1 (driver path_rules
     * stay empty = match all paths). The key formats for these are not
     * confirmed in the .xcf; see DESIGN.md section 8. */
}

/* Grab the first value in a section (used for the User section -> group). */
typedef struct { char *out; size_t cap; int found; } pb_first_ctx;

static void pb_first_key(const char *key, const char *value, void *ctx)
{
    pb_first_ctx *c = (pb_first_ctx *)ctx;
    (void)key;
    if (!c->found) {
        strncpy(c->out, value, c->cap - 1);
        c->out[c->cap - 1] = 0;
        c->found = 1;
    }
}

int policy_build_from_xcf(const xcf_t *x, WWFLT_POLICY **out_policy,
                          ULONG *out_count, char *out_group, size_t out_group_cap,
                          char *err, size_t err_cap)
{
    pb_table_t *t = NULL;
    char group_gbk[128] = { 0 };
    WWFLT_POLICY *pol = NULL;
    pb_collect_ctx cc;
    pb_first_ctx fc;
    int i;

    if (!x || !x->text || !out_policy) {
        if (err) snprintf(err, err_cap, "bad arguments");
        return -1;
    }
    t = (pb_table_t *)calloc(1, sizeof(pb_table_t));
    if (!t) { if (err) snprintf(err, err_cap, "out of memory"); return -1; }

    /* 1. Kernel (main policy). */
    cc.t = t;
    pb_walk_section(x, "Kernel", pb_collect_key, &cc);

    /* 2. Active group from the User section (first entry). */
    fc.out = group_gbk; fc.cap = sizeof(group_gbk); fc.found = 0;
    pb_walk_section(x, "User", pb_first_key, &fc);
    if (fc.found && group_gbk[0]) {
        /* 3. Overlay the group's rules (group wins for programs it lists). */
        pb_walk_section(x, group_gbk, pb_collect_key, &cc);
    } else {
        strncpy(group_gbk, "Kernel", sizeof(group_gbk) - 1);
    }
    if (out_group && out_group_cap) {
        strncpy(out_group, group_gbk, out_group_cap - 1);
        out_group[out_group_cap - 1] = 0;
    }

    /* 4. Build the WWFLT_POLICY (heap-allocated; ~1MB with the current limits). */
    pol = (WWFLT_POLICY *)calloc(1, sizeof(WWFLT_POLICY));
    if (!pol) { free(t); if (err) snprintf(err, err_cap, "out of memory (policy)"); return -1; }
    pol->version = 1;
    /* Group name: GBK -> WCHAR (code page 936). Fall back to empty on failure. */
    {
        int nw = MultiByteToWideChar(936, 0, group_gbk, -1, pol->group, WWFLT_MAX_GROUP_LEN);
        if (nw <= 0) pol->group[0] = 0;
    }
    pol->proc_count = 0;
    for (i = 0; i < t->count; i++) {
        WWFLT_PROC_RULE *pr;
        pb_rule_t *r = &t->rules[i];
        if (r->mode == WWFLT_ENCRYPT_NONE) continue;  /* skip programs with no Encrypt rule */
        if (pol->proc_count >= WWFLT_MAX_PROCESSES) break;
        pr = &pol->procs[pol->proc_count++];
        ascii_to_wide(r->exe, pr->exe, WWFLT_MAX_EXE_LEN);
        pr->encrypt_mode = r->mode;
        if (r->has_ext) ascii_to_wide(r->ext_list, pr->ext_list, sizeof(pr->ext_list) / sizeof(WCHAR));
        else pr->ext_list[0] = 0;
        pr->path_rule_count = 0;  /* Phase 1: match all paths */
    }
    free(t);
    *out_policy = pol;
    if (out_count) *out_count = pol->proc_count;
    return 0;
}

int policy_fetch_from_server(const char *server_url, WWFLT_POLICY **out_policy,
                             char *err, size_t err_cap)
{
    (void)server_url; (void)out_policy;
    if (err) snprintf(err, err_cap, "server policy fetch not configured (Phase 1: use local .xcf)");
    return -1;
}
