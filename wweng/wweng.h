/* wweng.h -- engine DLL (user mode) for the new WaterWall client.
 * Architecture (vendor-style, all our own code):
 *   - an injection driver loads this DLL into target processes;
 *   - the DLL hooks file APIs (CreateFile/ReadFile/WriteFile/...) via
 *     Microsoft Detours (inline/trampoline patching of the function
 *     body), the same mechanism the vendor engine uses, and does
 *     transparent encryption/decryption per .xcf policy. IAT patching
 *     was dropped: Win10 imports file APIs from API-set DLLs, so an
 *     IAT filter on kernel32.dll silently skipped every file API.
 *
 * File format (matches the old client, so files stay compatible):
 *   512-byte header + ciphertext. Header: 16-byte magic, version u16 at
 *   +0x10 (1 -> table A, 2 -> table B), policy name ASCII at +0x12,
 *   32-byte key as-is at +0x30. Header bytes +0x12..0x1ff are encrypted
 *   with counter starting at 0. Data starts at physical offset 512;
 *   the stream-cipher counter for a byte is its LOGICAL file offset.
 *
 * The app sees the logical view (no header). Physical offset = logical
 * offset + 512. GetFileSize reports logical size (physical - 512).
 * SetFilePointer offsets are translated the same way.
 */
#pragma once
#include <windows.h>
#include "wwflt.h"
#include "sbox.h"

/* Per-HANDLE encryption state. Kept in a global list guarded by
 * gCtxLock. Freed on CloseHandle. */
typedef struct _WW_FILE_CTX {
    HANDLE hFile;
    BOOL is_encrypted;      /* file has (or will get) a header */
    ULONG mode;             /* WWFLT_ENCRYPT_READ / WRITE */
    WW_SBOX_CTX sbox;
    int version;            /* 1 or 2 */
    WCHAR policy_name[WWFLT_MAX_GROUP_LEN];
    struct _WW_FILE_CTX *next;
} WW_FILE_CTX;

/* The active policy table (built from .xcf at DLL attach). NULL if the
 * policy could not be loaded; then every file passes through. */
extern WWFLT_POLICY *gPolicy;
extern CRITICAL_SECTION gPolicyLock;

/* Log to wweng.log next to the DLL (level 2 = policy decisions + crypto
 * events, level 1 = errors only). Never logs file content. */
void WwEngLog(int level, const char *fmt, ...);

/* Policy evaluation: does `exe` + `full_path` match a rule? On match,
 * fills *out_mode and the header policy name (exe uppercased + '.').
 * Returns TRUE on match. */
BOOL WwEngEvaluatePolicy(const WCHAR *exe, const WCHAR *full_path,
                         ULONG *out_mode, WCHAR *out_policy_name, size_t policy_chars);

/* Build a 512-byte header for a new encrypted file. */
void WwEngBuildHeader(UCHAR hdr[WWFLT_HEADER_SIZE], const char *policy_name,
                      const UCHAR key[WWFLT_KEY_SIZE]);

/* Parse a header read from disk. Returns TRUE if the magic matches and
 * the version is known; fills key + version. The header bytes
 * +0x12..0x1ff are decrypted in place. */
BOOL WwEngParseHeader(UCHAR hdr[WWFLT_HEADER_SIZE], UCHAR key[WWFLT_KEY_SIZE],
                      int *version);

/* Fill `key` with 32 random bytes (RtlGenRandom). */
void WwEngRandomKey(UCHAR key[WWFLT_KEY_SIZE]);

/* File-context list helpers (gCtxLock must be held by the caller unless
 * noted). */
WW_FILE_CTX *WwEngFindCtx(HANDLE h);
void WwEngInsertCtx(WW_FILE_CTX *ctx);
void WwEngRemoveCtx(HANDLE h);
