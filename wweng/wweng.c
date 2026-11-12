/* wweng.c -- engine DLL. Hooks file APIs via IAT patching and does
 * transparent encryption/decryption per .xcf policy.
 *
 * Notes / Phase 1 limits:
 * - Only synchronous (non-overlapped) ReadFile/WriteFile are filtered.
 *   Overlapped I/O passes through unfiltered.
 * - Existing plaintext files are NOT converted (a Write-mode file that
 *   has no header stays plaintext). New files get a header.
 * - The per-handle context list is guarded by gCtxLock, held during a
 *   whole hooked call (simple; Notepad is single-threaded for file I/O).
 * - Internal file I/O (policy load, logging) always uses the saved
 *   ORIGINAL function pointers, never the hooked ones.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wweng.h"
#include "iat.h"
#include "policy_build.h"
#include "xcf.h"

/* ---- originals (filled by the IAT hook table) ---- */
static HANDLE (WINAPI *gOrigCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = NULL;
static HANDLE (WINAPI *gOrigCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = NULL;
static BOOL (WINAPI *gOrigReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = NULL;
static BOOL (WINAPI *gOrigWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = NULL;
static BOOL (WINAPI *gOrigCloseHandle)(HANDLE) = NULL;
static DWORD (WINAPI *gOrigSetFilePointer)(HANDLE, LONG, PLONG, DWORD) = NULL;
static BOOL (WINAPI *gOrigSetFilePointerEx)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD) = NULL;
static DWORD (WINAPI *gOrigGetFileSize)(HANDLE, LPDWORD) = NULL;
static BOOL (WINAPI *gOrigGetFileSizeEx)(HANDLE, PLARGE_INTEGER) = NULL;
static BOOL (WINAPI *gOrigSetEndOfFile)(HANDLE) = NULL;
static HMODULE (WINAPI *gOrigLoadLibraryW)(LPCWSTR) = NULL;
static HMODULE (WINAPI *gOrigLoadLibraryA)(LPCSTR) = NULL;
static HMODULE (WINAPI *gOrigLoadLibraryExW)(LPCWSTR, HANDLE, DWORD) = NULL;

/* ---- globals ---- */
static HMODULE gOwnModule = NULL;
static CRITICAL_SECTION gCtxLock;
static WW_FILE_CTX *gCtxList = NULL;
static LONG gInitDone = 0;
static int gLogLevel = 2;
static WCHAR gLogPath[MAX_PATH] = L"";
static WCHAR gXcfPath[MAX_PATH] = L"";

/* ---- logging ---- */
void WwEngLog(int level, const char *fmt, ...)
{
    FILE *f;
    char buf[1024];
    va_list ap;
    SYSTEMTIME st;
    if (level > gLogLevel) return;
    if (!gLogPath[0]) return;
    GetLocalTime(&st);
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    f = _wfopen(gLogPath, L"a");
    if (!f) return;
    fprintf(f, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, buf);
    fclose(f);
}

/* ---- context list ---- */
WW_FILE_CTX *WwEngFindCtx(HANDLE h)
{
    WW_FILE_CTX *c;
    for (c = gCtxList; c; c = c->next) {
        if (c->hFile == h) return c;
    }
    return NULL;
}

void WwEngInsertCtx(WW_FILE_CTX *ctx)
{
    ctx->next = gCtxList;
    gCtxList = ctx;
}

void WwEngRemoveCtx(HANDLE h)
{
    WW_FILE_CTX **pp = &gCtxList;
    while (*pp) {
        if ((*pp)->hFile == h) {
            WW_FILE_CTX *dead = *pp;
            *pp = dead->next;
            free(dead);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ---- helpers ---- */
static void GetOwnExeName(WCHAR *out, size_t chars)
{
    WCHAR path[MAX_PATH];
    WCHAR *slash;
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (!n) { out[0] = L'\0'; return; }
    slash = wcsrchr(path, L'\\');
    {
        const WCHAR *base = slash ? slash + 1 : path;
        wcsncpy(out, base, chars - 1);
        out[chars - 1] = L'\0';
    }
}

static void PolicyNameToAscii(const WCHAR *wname, char *out, size_t cap)
{
    size_t i = 0;
    while (wname[i] && i + 1 < cap) {
        WCHAR c = wname[i];
        out[i] = (char)(c < 128 ? c : '?');
        i++;
    }
    out[i] = '\0';
}

/* Load the policy from the .xcf next to this DLL (or gXcfPath). Called
 * once, lazily, from the first hooked call. Uses ORIGINAL file APIs. */
static void WwEngLoadPolicy(void)
{
    xcf_t x;
    WWFLT_POLICY *pol = NULL;
    ULONG count = 0;
    char group[128] = "";
    char err[256] = "";
    WCHAR dllPath[MAX_PATH];
    WCHAR *slash;
    int rc;

    if (gPolicy) return;
    /* Resolve the .xcf path: same directory as this DLL. */
    if (!gXcfPath[0]) {
        DWORD n = GetModuleFileNameW(gOwnModule, dllPath, MAX_PATH);
        if (n && n < MAX_PATH) {
            slash = wcsrchr(dllPath, L'\\');
            if (slash) {
                size_t dirlen = (size_t)(slash - dllPath + 1);
                if (dirlen + 10 < MAX_PATH) {
                    wcsncpy(gXcfPath, dllPath, dirlen);
                    gXcfPath[dirlen] = L'\0';
                    wcscat(gXcfPath, L"wwkrn.xcf");
                }
            }
        }
        if (!gXcfPath[0]) {
            wcscpy(gXcfPath, L"C:\\vis\\wwkrn.xcf");
        }
    }
    /* Log path: wweng.log next to the DLL. */
    if (!gLogPath[0]) {
        DWORD n = GetModuleFileNameW(gOwnModule, dllPath, MAX_PATH);
        if (n && n < MAX_PATH) {
            slash = wcsrchr(dllPath, L'\\');
            if (slash) {
                size_t dirlen = (size_t)(slash - dllPath + 1);
                if (dirlen + 10 < MAX_PATH) {
                    wcsncpy(gLogPath, dllPath, dirlen);
                    gLogPath[dirlen] = L'\0';
                    wcscat(gLogPath, L"wweng.log");
                }
            }
        }
    }
    /* Convert the wide path to UTF-8/ANSI for xcf_load (it takes char*). */
    {
        char xcfAnsi[MAX_PATH * 2];
        WideCharToMultiByte(CP_ACP, 0, gXcfPath, -1, xcfAnsi, sizeof(xcfAnsi), NULL, NULL);
        rc = xcf_load(xcfAnsi, &x);
        if (rc != 0) {
            WwEngLog(1, "policy: xcf_load failed (%d) path=%s", rc, xcfAnsi);
            return;
        }
        rc = policy_build_from_xcf(&x, &pol, &count, group, sizeof(group),
                                   "Kernel", err, sizeof(err));
        xcf_free(&x);
        if (rc != 0) {
            WwEngLog(1, "policy: build failed: %s", err);
            return;
        }
        gPolicy = pol;
        WwEngLog(2, "policy: loaded group='%s' %lu rules", group, count);
    }
}

static void WwEngEnsureInit(void)
{
    if (InterlockedCompareExchange(&gInitDone, 1, 0) == 0) {
        WwEngLoadPolicy();
    }
}

/* ---- create-time handling ---- */
static void WwEngOnCreate(HANDLE h, LPCWSTR lpFileName, DWORD dwDesiredAccess,
                          DWORD dwCreationDisposition)
{
    WCHAR exe[WWFLT_MAX_EXE_LEN];
    ULONG mode = WWFLT_ENCRYPT_NONE;
    WCHAR policy_name[WWFLT_MAX_GROUP_LEN];
    LARGE_INTEGER fileSize;
    WW_FILE_CTX *ctx = NULL;
    UCHAR hdr[WWFLT_HEADER_SIZE];
    UCHAR key[WWFLT_KEY_SIZE];
    int version = 0;
    DWORD read = 0;
    BOOL ok;

    (void)dwCreationDisposition;
    if (!gPolicy) return;
    /* Only regular files the app can read/write matter. Directories and
     * non-disk handles are skipped by checking the file type. */
    if (GetFileType(h) != FILE_TYPE_DISK) return;
    GetOwnExeName(exe, WWFLT_MAX_EXE_LEN);
    if (!WwEngEvaluatePolicy(exe, lpFileName, &mode, policy_name,
                             WWFLT_MAX_GROUP_LEN)) {
        return;
    }
    /* Get the file size. */
    if (!gOrigGetFileSizeEx(h, &fileSize)) return;
    if (fileSize.QuadPart == 0) {
        /* New (or truncated) file. Only WRITE mode creates a header. */
        char asciiPolicy[WWFLT_MAX_GROUP_LEN];
        DWORD written = 0;
        LARGE_INTEGER zero;
        if (mode != WWFLT_ENCRYPT_WRITE) return;
        if (!(dwDesiredAccess & GENERIC_WRITE)) return;
        WwEngRandomKey(key);
        PolicyNameToAscii(policy_name, asciiPolicy, sizeof(asciiPolicy));
        WwEngBuildHeader(hdr, asciiPolicy, key);
        zero.QuadPart = 0;
        gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
        ok = gOrigWriteFile(h, hdr, WWFLT_HEADER_SIZE, &written, NULL);
        if (!ok || written != WWFLT_HEADER_SIZE) {
            WwEngLog(1, "create: header write failed for %ls", lpFileName);
            return;
        }
        ctx = (WW_FILE_CTX *)calloc(1, sizeof(WW_FILE_CTX));
        if (!ctx) return;
        ctx->hFile = h;
        ctx->is_encrypted = TRUE;
        ctx->mode = mode;
        ctx->version = WWFLT_CURRENT_VERSION;
        wcscpy(ctx->policy_name, policy_name);
        WwSboxInit(&ctx->sbox, ctx->version, key);
        EnterCriticalSection(&gCtxLock);
        WwEngInsertCtx(ctx);
        LeaveCriticalSection(&gCtxLock);
        WwEngLog(2, "create: new encrypted %ls mode=%lu", lpFileName, mode);
        return;
    }
    if (fileSize.QuadPart < WWFLT_HEADER_SIZE) {
        /* Too small to carry a header: plaintext, no conversion. */
        return;
    }
    /* Existing file: probe the first 512 bytes for the magic. */
    {
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
        ok = gOrigReadFile(h, hdr, WWFLT_HEADER_SIZE, &read, NULL);
        if (!ok || read != WWFLT_HEADER_SIZE) {
            gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
            return;
        }
        if (!WwEngParseHeader(hdr, key, &version)) {
            /* Not an encrypted file: restore position to 0 and pass through. */
            gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
            return;
        }
        /* Encrypted: position is already at 512 (logical 0). Keep it. */
        ctx = (WW_FILE_CTX *)calloc(1, sizeof(WW_FILE_CTX));
        if (!ctx) {
            gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
            return;
        }
        ctx->hFile = h;
        ctx->is_encrypted = TRUE;
        ctx->mode = mode;
        ctx->version = version;
        wcscpy(ctx->policy_name, policy_name);
        WwSboxInit(&ctx->sbox, version, key);
        EnterCriticalSection(&gCtxLock);
        WwEngInsertCtx(ctx);
        LeaveCriticalSection(&gCtxLock);
        WwEngLog(2, "create: opened encrypted %ls version=%d mode=%lu",
                 lpFileName, version, mode);
    }
}

/* ---- hooks ---- */
static HANDLE WINAPI WwHookCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE h;
    WwEngEnsureInit();
    h = gOrigCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                         lpSecurityAttributes, dwCreationDisposition,
                         dwFlagsAndAttributes, hTemplateFile);
    if (h == INVALID_HANDLE_VALUE) return h;
    EnterCriticalSection(&gCtxLock);
    WwEngOnCreate(h, lpFileName, dwDesiredAccess, dwCreationDisposition);
    LeaveCriticalSection(&gCtxLock);
    return h;
}

static HANDLE WINAPI WwHookCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE h;
    WCHAR wname[MAX_PATH];
    WwEngEnsureInit();
    h = gOrigCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                         lpSecurityAttributes, dwCreationDisposition,
                         dwFlagsAndAttributes, hTemplateFile);
    if (h == INVALID_HANDLE_VALUE) return h;
    if (MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wname, MAX_PATH) > 0) {
        EnterCriticalSection(&gCtxLock);
        WwEngOnCreate(h, wname, dwDesiredAccess, dwCreationDisposition);
        LeaveCriticalSection(&gCtxLock);
    }
    return h;
}

static BOOL WINAPI WwHookReadFile(HANDLE hFile, LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    WW_FILE_CTX *ctx;
    DWORD read = 0;
    BOOL ok;
    ULONGLONG logical_off;
    LARGE_INTEGER cur, zero;

    if (lpOverlapped) {
        return gOrigReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
                             lpNumberOfBytesRead, lpOverlapped);
    }
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(hFile);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
                             lpNumberOfBytesRead, lpOverlapped);
    }
    zero.QuadPart = 0;
    if (!gOrigSetFilePointerEx(hFile, zero, &cur, FILE_CURRENT)) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
                             lpNumberOfBytesRead, lpOverlapped);
    }
    if (cur.QuadPart < WWFLT_HEADER_SIZE) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
                             lpNumberOfBytesRead, lpOverlapped);
    }
    logical_off = (ULONGLONG)(cur.QuadPart - WWFLT_HEADER_SIZE);
    ok = gOrigReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &read, NULL);
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = read;
    if (ok && read > 0) {
        WwSboxDecrypt(&ctx->sbox, (unsigned char *)lpBuffer, read, logical_off);
    }
    LeaveCriticalSection(&gCtxLock);
    return ok;
}

static BOOL WINAPI WwHookWriteFile(HANDLE hFile, LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    WW_FILE_CTX *ctx;
    DWORD written = 0;
    BOOL ok;
    ULONGLONG logical_off;
    LARGE_INTEGER cur, zero;
    unsigned char *tmp = NULL;

    if (lpOverlapped) {
        return gOrigWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                              lpNumberOfBytesWritten, lpOverlapped);
    }
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(hFile);
    if (!ctx || !ctx->is_encrypted || ctx->mode != WWFLT_ENCRYPT_WRITE) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                              lpNumberOfBytesWritten, lpOverlapped);
    }
    zero.QuadPart = 0;
    if (!gOrigSetFilePointerEx(hFile, zero, &cur, FILE_CURRENT)) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                              lpNumberOfBytesWritten, lpOverlapped);
    }
    if (cur.QuadPart < WWFLT_HEADER_SIZE) {
        /* Writing inside the header region: pass through (shouldn't happen). */
        LeaveCriticalSection(&gCtxLock);
        return gOrigWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                              lpNumberOfBytesWritten, lpOverlapped);
    }
    logical_off = (ULONGLONG)(cur.QuadPart - WWFLT_HEADER_SIZE);
    tmp = (unsigned char *)malloc(nNumberOfBytesToWrite ? nNumberOfBytesToWrite : 1);
    if (!tmp) {
        LeaveCriticalSection(&gCtxLock);
        if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    memcpy(tmp, lpBuffer, nNumberOfBytesToWrite);
    WwSboxEncrypt(&ctx->sbox, tmp, nNumberOfBytesToWrite, logical_off);
    ok = gOrigWriteFile(hFile, tmp, nNumberOfBytesToWrite, &written, NULL);
    free(tmp);
    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = written;
    LeaveCriticalSection(&gCtxLock);
    return ok;
}

static BOOL WINAPI WwHookCloseHandle(HANDLE hObject)
{
    BOOL ok;
    EnterCriticalSection(&gCtxLock);
    WwEngRemoveCtx(hObject);
    LeaveCriticalSection(&gCtxLock);
    ok = gOrigCloseHandle(hObject);
    return ok;
}

static DWORD WINAPI WwHookSetFilePointer(HANDLE hFile, LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    WW_FILE_CTX *ctx;
    DWORD r;
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(hFile);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigSetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
    }
    /* Translate the logical offset to a physical one (+512). */
    {
        LARGE_INTEGER logical, physical, res;
        LONG high = lpDistanceToMoveHigh ? *lpDistanceToMoveHigh : 0;
        logical.LowPart = (DWORD)lDistanceToMove;
        logical.HighPart = high;
        if (dwMoveMethod == FILE_BEGIN) {
            physical.QuadPart = logical.QuadPart + WWFLT_HEADER_SIZE;
            if (!gOrigSetFilePointerEx(hFile, physical, &res, FILE_BEGIN)) {
                LeaveCriticalSection(&gCtxLock);
                return INVALID_SET_FILE_POINTER;
            }
            res.QuadPart -= WWFLT_HEADER_SIZE;
            if (lpDistanceToMoveHigh) *lpDistanceToMoveHigh = res.HighPart;
            r = res.LowPart;
        } else if (dwMoveMethod == FILE_CURRENT) {
            /* Current physical position already includes the header. */
            physical.QuadPart = logical.QuadPart;
            if (!gOrigSetFilePointerEx(hFile, physical, &res, FILE_CURRENT)) {
                LeaveCriticalSection(&gCtxLock);
                return INVALID_SET_FILE_POINTER;
            }
            res.QuadPart -= WWFLT_HEADER_SIZE;
            if (lpDistanceToMoveHigh) *lpDistanceToMoveHigh = res.HighPart;
            r = res.LowPart;
        } else { /* FILE_END */
            /* End is physical_size - 512 (logical). Seek relative to the
             * physical end by the same delta. */
            physical.QuadPart = logical.QuadPart;
            if (!gOrigSetFilePointerEx(hFile, physical, &res, FILE_END)) {
                LeaveCriticalSection(&gCtxLock);
                return INVALID_SET_FILE_POINTER;
            }
            res.QuadPart -= WWFLT_HEADER_SIZE;
            if (lpDistanceToMoveHigh) *lpDistanceToMoveHigh = res.HighPart;
            r = res.LowPart;
        }
    }
    LeaveCriticalSection(&gCtxLock);
    return r;
}

static BOOL WINAPI WwHookSetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove,
    PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
{
    WW_FILE_CTX *ctx;
    BOOL ok;
    LARGE_INTEGER physical, res;
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(hFile);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigSetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
    }
    if (dwMoveMethod == FILE_BEGIN) {
        physical.QuadPart = liDistanceToMove.QuadPart + WWFLT_HEADER_SIZE;
        ok = gOrigSetFilePointerEx(hFile, physical, &res, FILE_BEGIN);
        if (ok && lpNewFilePointer) {
            lpNewFilePointer->QuadPart = res.QuadPart - WWFLT_HEADER_SIZE;
        }
    } else {
        ok = gOrigSetFilePointerEx(hFile, liDistanceToMove, &res, dwMoveMethod);
        if (ok && lpNewFilePointer) {
            lpNewFilePointer->QuadPart = res.QuadPart - WWFLT_HEADER_SIZE;
        }
    }
    LeaveCriticalSection(&gCtxLock);
    return ok;
}

static DWORD WINAPI WwHookGetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
{
    WW_FILE_CTX *ctx;
    DWORD r;
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(hFile);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigGetFileSize(hFile, lpFileSizeHigh);
    }
    {
        LARGE_INTEGER sz;
        if (!gOrigGetFileSizeEx(hFile, &sz)) {
            LeaveCriticalSection(&gCtxLock);
            return gOrigGetFileSize(hFile, lpFileSizeHigh);
        }
        if (sz.QuadPart >= WWFLT_HEADER_SIZE) sz.QuadPart -= WWFLT_HEADER_SIZE;
        else sz.QuadPart = 0;
        if (lpFileSizeHigh) *lpFileSizeHigh = (DWORD)sz.HighPart;
        r = (DWORD)sz.LowPart;
    }
    LeaveCriticalSection(&gCtxLock);
    return r;
}

static BOOL WINAPI WwHookGetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)
{
    WW_FILE_CTX *ctx;
    BOOL ok;
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(hFile);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigGetFileSizeEx(hFile, lpFileSize);
    }
    ok = gOrigGetFileSizeEx(hFile, lpFileSize);
    if (ok && lpFileSize) {
        if (lpFileSize->QuadPart >= WWFLT_HEADER_SIZE) lpFileSize->QuadPart -= WWFLT_HEADER_SIZE;
        else lpFileSize->QuadPart = 0;
    }
    LeaveCriticalSection(&gCtxLock);
    return ok;
}

static BOOL WINAPI WwHookSetEndOfFile(HANDLE hFile)
{
    WW_FILE_CTX *ctx;
    BOOL ok;
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(hFile);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigSetEndOfFile(hFile);
    }
    /* Current physical position already includes the header; truncate
     * there. The logical size becomes physical - 512. */
    ok = gOrigSetEndOfFile(hFile);
    LeaveCriticalSection(&gCtxLock);
    return ok;
}

static HMODULE WINAPI WwHookLoadLibraryW(LPCWSTR lpLibFileName)
{
    HMODULE m = gOrigLoadLibraryW(lpLibFileName);
    if (m) {
        extern const WW_IAT_HOOK gHooks[];
        extern const int gHookCount;
        WwIatHookModule(m, gHooks, gHookCount);
    }
    return m;
}

static HMODULE WINAPI WwHookLoadLibraryA(LPCSTR lpLibFileName)
{
    HMODULE m = gOrigLoadLibraryA(lpLibFileName);
    if (m) {
        extern const WW_IAT_HOOK gHooks[];
        extern const int gHookCount;
        WwIatHookModule(m, gHooks, gHookCount);
    }
    return m;
}

static HMODULE WINAPI WwHookLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE m = gOrigLoadLibraryExW(lpLibFileName, hFile, dwFlags);
    if (m) {
        extern const WW_IAT_HOOK gHooks[];
        extern const int gHookCount;
        WwIatHookModule(m, gHooks, gHookCount);
    }
    return m;
}

/* ---- hook table ---- */
const WW_IAT_HOOK gHooks[] = {
    { "kernel32.dll", "CreateFileW", (void *)WwHookCreateFileW, (void **)&gOrigCreateFileW },
    { "kernel32.dll", "CreateFileA", (void *)WwHookCreateFileA, (void **)&gOrigCreateFileA },
    { "kernel32.dll", "ReadFile", (void *)WwHookReadFile, (void **)&gOrigReadFile },
    { "kernel32.dll", "WriteFile", (void *)WwHookWriteFile, (void **)&gOrigWriteFile },
    { "kernel32.dll", "CloseHandle", (void *)WwHookCloseHandle, (void **)&gOrigCloseHandle },
    { "kernel32.dll", "SetFilePointer", (void *)WwHookSetFilePointer, (void **)&gOrigSetFilePointer },
    { "kernel32.dll", "SetFilePointerEx", (void *)WwHookSetFilePointerEx, (void **)&gOrigSetFilePointerEx },
    { "kernel32.dll", "GetFileSize", (void *)WwHookGetFileSize, (void **)&gOrigGetFileSize },
    { "kernel32.dll", "GetFileSizeEx", (void *)WwHookGetFileSizeEx, (void **)&gOrigGetFileSizeEx },
    { "kernel32.dll", "SetEndOfFile", (void *)WwHookSetEndOfFile, (void **)&gOrigSetEndOfFile },
    { "kernel32.dll", "LoadLibraryW", (void *)WwHookLoadLibraryW, (void **)&gOrigLoadLibraryW },
    { "kernel32.dll", "LoadLibraryA", (void *)WwHookLoadLibraryA, (void **)&gOrigLoadLibraryA },
    { "kernel32.dll", "LoadLibraryExW", (void *)WwHookLoadLibraryExW, (void **)&gOrigLoadLibraryExW },
};
const int gHookCount = (int)(sizeof(gHooks) / sizeof(gHooks[0]));

/* ---- DllMain ---- */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        gOwnModule = (HMODULE)hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        InitializeCriticalSection(&gCtxLock);
        InitializeCriticalSection(&gPolicyLock);
        WwIatSetOwnModule(gOwnModule);
        /* Pre-fill originals from the real kernel32 in case a module has
         * no IAT entry for one of these (then the hook stays uninstalled
         * for that module but the original is still usable). */
        {
            HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
            if (k32) {
                if (!gOrigCreateFileW) gOrigCreateFileW = (void *)GetProcAddress(k32, "CreateFileW");
                if (!gOrigCreateFileA) gOrigCreateFileA = (void *)GetProcAddress(k32, "CreateFileA");
                if (!gOrigReadFile) gOrigReadFile = (void *)GetProcAddress(k32, "ReadFile");
                if (!gOrigWriteFile) gOrigWriteFile = (void *)GetProcAddress(k32, "WriteFile");
                if (!gOrigCloseHandle) gOrigCloseHandle = (void *)GetProcAddress(k32, "CloseHandle");
                if (!gOrigSetFilePointer) gOrigSetFilePointer = (void *)GetProcAddress(k32, "SetFilePointer");
                if (!gOrigSetFilePointerEx) gOrigSetFilePointerEx = (void *)GetProcAddress(k32, "SetFilePointerEx");
                if (!gOrigGetFileSize) gOrigGetFileSize = (void *)GetProcAddress(k32, "GetFileSize");
                if (!gOrigGetFileSizeEx) gOrigGetFileSizeEx = (void *)GetProcAddress(k32, "GetFileSizeEx");
                if (!gOrigSetEndOfFile) gOrigSetEndOfFile = (void *)GetProcAddress(k32, "SetEndOfFile");
                if (!gOrigLoadLibraryW) gOrigLoadLibraryW = (void *)GetProcAddress(k32, "LoadLibraryW");
                if (!gOrigLoadLibraryA) gOrigLoadLibraryA = (void *)GetProcAddress(k32, "LoadLibraryA");
                if (!gOrigLoadLibraryExW) gOrigLoadLibraryExW = (void *)GetProcAddress(k32, "LoadLibraryExW");
            }
        }
        WwIatHookAllModules(gHooks, gHookCount);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        /* Best effort: free contexts. Do not unpatch IATs. */
        WW_FILE_CTX *c, *next;
        EnterCriticalSection(&gCtxLock);
        for (c = gCtxList; c; c = next) {
            next = c->next;
            free(c);
        }
        gCtxList = NULL;
        LeaveCriticalSection(&gCtxLock);
        if (gPolicy) { free(gPolicy); gPolicy = NULL; }
        DeleteCriticalSection(&gCtxLock);
        DeleteCriticalSection(&gPolicyLock);
    }
    return TRUE;
}
