/* policy.c -- user-mode policy evaluation + header build/parse for the
 * engine DLL. Ported from wwflt.c (WwWcsIcmp / WwExtInList /
 * WwGetExtension / WwEvaluatePolicy / WwBuildHeader / WwParseHeader).
 * The policy table is loaded once from .xcf at DLL attach; evaluation
 * is a plain table lookup (no locks needed after load, the table is
 * read-only).
 */
#include "wweng.h"
#include <string.h>
#include <stdlib.h>

WWFLT_POLICY *gPolicy = NULL;
CRITICAL_SECTION gPolicyLock;

static WCHAR WwToLower(WCHAR c)
{
    if (c >= L'A' && c <= L'Z') return (WCHAR)(c + (L'a' - L'A'));
    return c;
}

static int WwWcsIcmp(PCWSTR a, PCWSTR b)
{
    while (*a && *b) {
        WCHAR ca = WwToLower(*a), cb = WwToLower(*b);
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)WwToLower(*a) - (int)WwToLower(*b);
}

static BOOL WwExtInList(PCWSTR ext_list, PCWSTR ext)
{
    PCWSTR p = ext_list;
    if (!ext || !*ext) return FALSE;
    while (*p) {
        PCWSTR start = p;
        size_t n = 0;
        while (*p && *p != L'|') { p++; n++; }
        if (n > 0 && n == wcslen(ext)) {
            size_t i;
            BOOL same = TRUE;
            for (i = 0; i < n; i++) {
                if (WwToLower(start[i]) != WwToLower(ext[i])) { same = FALSE; break; }
            }
            if (same) return TRUE;
        }
        if (*p == L'|') p++;
    }
    return FALSE;
}

static PCWSTR WwGetExtension(PCWSTR file_name, PWSTR ext_buf, size_t ext_chars)
{
    PCWSTR dot;
    PCWSTR slash;
    if (!file_name || !*file_name) return NULL;
    dot = wcsrchr(file_name, L'.');
    slash = wcsrchr(file_name, L'\\');
    if (!dot || (slash && dot < slash)) return NULL;
    dot++;
    if (!*dot) return NULL;
    wcsncpy(ext_buf, dot, ext_chars - 1);
    ext_buf[ext_chars - 1] = L'\0';
    return ext_buf;
}

/* Wildcard match ('*' and '?'), case-insensitive. Ported from wwflt.c. */
static BOOL WwWildcardMatch(PCWSTR pattern, PCWSTR str)
{
    PCWSTR p = pattern, s = str;
    PCWSTR star_p = NULL, star_s = NULL;
    while (*s) {
        if (*p == L'*') {
            star_p = p++;
            star_s = s;
        } else if (*p == L'?' || WwToLower(*p) == WwToLower(*s)) {
            p++; s++;
        } else if (star_p) {
            p = star_p + 1;
            s = ++star_s;
        } else {
            return FALSE;
        }
    }
    while (*p == L'*') p++;
    return *p == L'\0';
}

BOOL WwEngEvaluatePolicy(const WCHAR *exe, const WCHAR *full_path,
                         ULONG *out_mode, WCHAR *out_policy_name, size_t policy_chars)
{
    const WWFLT_PROC_RULE *rule = NULL;
    WCHAR ext[WWFLT_MAX_EXT_LEN];
    PCWSTR extp;
    ULONG i;
    BOOL path_ok = FALSE;

    if (!gPolicy) return FALSE;
    for (i = 0; i < gPolicy->proc_count; i++) {
        if (WwWcsIcmp(gPolicy->procs[i].exe, exe) == 0) {
            rule = &gPolicy->procs[i];
            break;
        }
    }
    if (!rule || rule->encrypt_mode == WWFLT_ENCRYPT_NONE) return FALSE;
    /* Extension must be in this process's File list. The file name is
     * the part after the last backslash. */
    {
        PCWSTR slash = wcsrchr(full_path, L'\\');
        PCWSTR name = slash ? slash + 1 : full_path;
        extp = WwGetExtension(name, ext, WWFLT_MAX_EXT_LEN);
    }
    if (!extp || !WwExtInList(rule->ext_list, extp)) return FALSE;
    /* Path must match at least one dir/wild/include rule (if any). */
    if (rule->path_rule_count == 0) {
        path_ok = TRUE;
    } else {
        for (i = 0; i < rule->path_rule_count; i++) {
            if (WwWildcardMatch(rule->path_rules[i], full_path)) { path_ok = TRUE; break; }
        }
    }
    if (!path_ok) return FALSE;
    *out_mode = rule->encrypt_mode;
    /* Policy name for the header: the exe name in uppercase + '.', e.g. L"NOTEPAD." */
    {
        size_t n = wcslen(exe);
        size_t j;
        if (n > policy_chars - 2) n = policy_chars - 2;
        for (j = 0; j < n; j++) {
            WCHAR c = exe[j];
            if (c == L'.') break;
            if (c >= L'a' && c <= L'z') c = (WCHAR)(c - (L'a' - L'A'));
            out_policy_name[j] = c;
        }
        out_policy_name[j] = L'.';
        out_policy_name[j + 1] = L'\0';
    }
    return TRUE;
}

static const unsigned char gMagic[WWFLT_MAGIC_SIZE] = WWFLT_MAGIC_BYTES;

void WwEngBuildHeader(UCHAR hdr[WWFLT_HEADER_SIZE], const char *policy_name,
                      const UCHAR key[WWFLT_KEY_SIZE])
{
    WW_SBOX_CTX tmp;
    size_t i, pn_len;
    memset(hdr, 0, WWFLT_HEADER_SIZE);
    memcpy(hdr, gMagic, WWFLT_MAGIC_SIZE);
    hdr[WWFLT_HEADER_VERSION_OFF] = (UCHAR)(WWFLT_CURRENT_VERSION & 0xff);
    hdr[WWFLT_HEADER_VERSION_OFF + 1] = (UCHAR)((WWFLT_CURRENT_VERSION >> 8) & 0xff);
    pn_len = strlen(policy_name);
    if (pn_len > (size_t)(WWFLT_HEADER_SIZE - WWFLT_HEADER_POLICY_OFF - 1)) {
        pn_len = WWFLT_HEADER_SIZE - WWFLT_HEADER_POLICY_OFF - 1;
    }
    memcpy(hdr + WWFLT_HEADER_POLICY_OFF, policy_name, pn_len);
    memcpy(hdr + WWFLT_HEADER_KEY_OFF, key, WWFLT_KEY_SIZE);
    /* Encrypt header bytes +0x12..0x30 and +0x50..0x1ff, counter =
     * offset-0x12. The key at +0x30..0x4f is stored in PLAINTEXT and
     * skipped -- verified byte-identical against the vendor's 1.txt
     * (re-encrypting a decrypted vendor header reproduces the raw
     * file only when the key is left plaintext). Encrypting the key
     * region (the old code did) makes our files unreadable by the
     * vendor client and garbles the policy name. */
    WwSboxInit(&tmp, WWFLT_CURRENT_VERSION, key);
    WwSboxEncrypt(&tmp, hdr + WWFLT_HEADER_POLICY_OFF,
                  WWFLT_HEADER_KEY_OFF - WWFLT_HEADER_POLICY_OFF, 0);
    WwSboxEncrypt(&tmp, hdr + WWFLT_HEADER_KEY_OFF + WWFLT_KEY_SIZE,
                  WWFLT_HEADER_SIZE - (WWFLT_HEADER_KEY_OFF + WWFLT_KEY_SIZE),
                  WWFLT_HEADER_KEY_OFF + WWFLT_KEY_SIZE - WWFLT_HEADER_POLICY_OFF);
    (void)i;
}

BOOL WwEngParseHeader(UCHAR hdr[WWFLT_HEADER_SIZE], UCHAR key[WWFLT_KEY_SIZE],
                      int *version)
{
    WW_SBOX_CTX tmp;
    if (memcmp(hdr, gMagic, WWFLT_MAGIC_SIZE) != 0) return FALSE;
    *version = hdr[WWFLT_HEADER_VERSION_OFF] | (hdr[WWFLT_HEADER_VERSION_OFF + 1] << 8);
    if (*version != WWFLT_VERSION_1 && *version != WWFLT_VERSION_2) return FALSE;
    /* The key is stored in PLAINTEXT; read it before decrypting. */
    memcpy(key, hdr + WWFLT_HEADER_KEY_OFF, WWFLT_KEY_SIZE);
    WwSboxInit(&tmp, *version, key);
    /* Decrypt +0x12..0x30 and +0x50..0x1ff, counter = offset-0x12.
     * The key region stays as-is (it is plaintext, not ciphertext). */
    WwSboxDecrypt(&tmp, hdr + WWFLT_HEADER_POLICY_OFF,
                  WWFLT_HEADER_KEY_OFF - WWFLT_HEADER_POLICY_OFF, 0);
    WwSboxDecrypt(&tmp, hdr + WWFLT_HEADER_KEY_OFF + WWFLT_KEY_SIZE,
                  WWFLT_HEADER_SIZE - (WWFLT_HEADER_KEY_OFF + WWFLT_KEY_SIZE),
                  WWFLT_HEADER_KEY_OFF + WWFLT_KEY_SIZE - WWFLT_HEADER_POLICY_OFF);
    return TRUE;
}

typedef BOOLEAN (WINAPI *RtlGenRandom_t)(PVOID, ULONG);

void WwEngRandomKey(UCHAR key[WWFLT_KEY_SIZE])
{
    static RtlGenRandom_t fn = NULL;
    if (!fn) {
        HMODULE adv = GetModuleHandleW(L"advapi32.dll");
        if (adv) fn = (RtlGenRandom_t)GetProcAddress(adv, "SystemFunction036");
    }
    if (fn && fn(key, WWFLT_KEY_SIZE)) return;
    /* Fallback: weak, but only used if RtlGenRandom is unavailable. */
    {
        unsigned int seed = (unsigned int)(GetTickCount() ^ GetCurrentProcessId() ^
                                            (ULONG_PTR)key);
        int i;
        srand(seed);
        for (i = 0; i < WWFLT_KEY_SIZE; i++) key[i] = (UCHAR)(rand() & 0xff);
    }
}
