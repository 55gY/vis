/* wweng.c -- engine DLL. Hooks file APIs via Microsoft Detours
 * (inline/trampoline patching of the function body in kernelbase.dll)
 * and does transparent encryption/decryption per .xcf policy.
 *
 * Why Detours, not IAT: the vendor engine (wwkrn64.dll) hooks with
 * Detours, and IAT patching is fragile on Win10 -- Notepad imports
 * CreateFileW/ReadFile/WriteFile from API-set DLLs
 * (api-ms-win-core-file-l1-1-0.dll), not kernel32.dll, so an IAT
 * filter on dll=="kernel32.dll" silently skips every file-API import
 * (wwnew-5/wweng-2.log: iat_patched=9 but zero 'hook: CreateFileW').
 * Detours patches the function body itself, so every caller is
 * intercepted regardless of import path. Newly loaded modules need no
 * re-patching (they call the same function body), so there is no
 * LoadLibrary hook any more.
 *
 * Notes / Phase 1 limits:
 * - Only synchronous (non-overlapped) ReadFile/WriteFile are filtered.
 *   Overlapped I/O passes through unfiltered.
 * - Existing plaintext files are NOT converted (a Write-mode file that
 *   has no header stays plaintext). New files get a header.
 * - The per-handle context list is guarded by gCtxLock, held during a
 *   whole hooked call (simple; Notepad is single-threaded for file I/O).
 * - Internal file I/O (policy load, logging) always uses the saved
 *   ORIGINAL function pointers (now the Detours trampolines), never the
 *   hooked ones.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wweng.h"
#include "detours/detours.h"
#include "policy_build.h"
#include "xcf.h"

/* ---- originals (Detours trampolines; filled by DetourAttach) ---- */
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

/* ---- NT layer (ntdll.dll) ----
 * The vendor hooks Nt* (not Win32): Notepad reads via NtReadFile and
 * memory mapping, which bypass a Win32-only ReadFile hook. These
 * Detours hooks share the same context list / policy evaluation as
 * the Win32 hooks. Async I/O (Event/ApcRoutine set) passes through,
 * like overlapped I/O in the Win32 hooks. */
typedef LONG NTSTATUS;
#define WW_NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
typedef struct _WW_IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} WW_IO_STATUS_BLOCK, *PWW_IO_STATUS_BLOCK;
typedef struct _WW_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} WW_UNICODE_STRING, *PWW_UNICODE_STRING;
typedef struct _WW_OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PWW_UNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} WW_OBJECT_ATTRIBUTES, *PWW_OBJECT_ATTRIBUTES;
typedef struct _WW_FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} WW_FILE_POSITION_INFORMATION;
typedef struct _WW_FILE_END_OF_FILE_INFORMATION {
    LARGE_INTEGER EndOfFile;
} WW_FILE_END_OF_FILE_INFORMATION;
typedef struct _WW_FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} WW_FILE_STANDARD_INFORMATION;
typedef enum _WW_FILE_INFORMATION_CLASS {
    WW_FileStandardInformation = 5,
    WW_FilePositionInformation = 14,
    WW_FileEndOfFileInformation = 20
} WW_FILE_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, PWW_OBJECT_ATTRIBUTES, PWW_IO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtOpenFile_t)(PHANDLE, ACCESS_MASK, PWW_OBJECT_ATTRIBUTES, PWW_IO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtReadFile_t)(HANDLE, HANDLE, PVOID, PVOID, PWW_IO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *NtWriteFile_t)(HANDLE, HANDLE, PVOID, PVOID, PWW_IO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtSetInformationFile_t)(HANDLE, PWW_IO_STATUS_BLOCK, PVOID, ULONG, WW_FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *NtQueryInformationFile_t)(HANDLE, PWW_IO_STATUS_BLOCK, PVOID, ULONG, WW_FILE_INFORMATION_CLASS);

static NtCreateFile_t gOrigNtCreateFile = NULL;
static NtOpenFile_t gOrigNtOpenFile = NULL;
static NtReadFile_t gOrigNtReadFile = NULL;
static NtWriteFile_t gOrigNtWriteFile = NULL;
static NtClose_t gOrigNtClose = NULL;
static NtSetInformationFile_t gOrigNtSetInformationFile = NULL;
static NtQueryInformationFile_t gOrigNtQueryInformationFile = NULL;

/* Convert an NT path (\??\C:\... or \DosDevices\C:\...) to a Win32
 * path (C:\...). Returns FALSE if it is not a Win32-style path. */
static BOOL NtPathToWin32(PWW_UNICODE_STRING name, WCHAR *out, size_t chars)
{
    const WCHAR *p;
    size_t len;
    if (!name || !name->Buffer || name->Length == 0) return FALSE;
    p = name->Buffer;
    len = name->Length / sizeof(WCHAR);
    if (len >= 4 && p[0] == L'\\' && p[1] == L'?' && p[2] == L'?' && p[3] == L'\\') {
        p += 4; len -= 4;
        /* \??\UNC\server\share -> \\server\share */
        if (len >= 4 && (p[0] == L'U' || p[0] == L'u') && (p[1] == L'N' || p[1] == L'n') &&
            (p[2] == L'C' || p[2] == L'c') && p[3] == L'\\') {
            if (chars < len - 2) return FALSE;
            out[0] = L'\\'; out[1] = L'\\';
            wcsncpy(out + 2, p + 4, chars - 3);
            out[chars - 1] = L'\0';
            return TRUE;
        }
    } else if (len >= 13 && _wcsnicmp(p, L"\\DosDevices\\", 12) == 0) {
        p += 12; len -= 12;
    } else {
        return FALSE;
    }
    if (len >= chars) return FALSE;
    wcsncpy(out, p, chars - 1);
    out[chars - 1] = L'\0';
    return TRUE;
}

/* Current physical file position via the original NtQueryInformationFile. */
static BOOL NtGetPosition(HANDLE h, LONGLONG *pos)
{
    WW_IO_STATUS_BLOCK iosb;
    WW_FILE_POSITION_INFORMATION pi;
    NTSTATUS st;
    if (!gOrigNtQueryInformationFile) return FALSE;
    st = gOrigNtQueryInformationFile(h, &iosb, &pi, sizeof(pi), WW_FilePositionInformation);
    if (!WW_NT_SUCCESS(st)) return FALSE;
    *pos = pi.CurrentByteOffset.QuadPart;
    return TRUE;
}

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

/* Log path: wweng.log next to the DLL. Set up eagerly in DllMain so
 * the log exists even if no hooked file call ever happens (the lazy
 * policy load alone cannot prove the DLL was injected). */
static void WwEngInitLogPath(void)
{
    WCHAR dllPath[MAX_PATH];
    WCHAR *slash;
    if (gLogPath[0]) return;
    {
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
    if (!gLogPath[0]) {
        wcscpy(gLogPath, L"C:\\vis\\wweng.log");
    }
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
    /* Log path: wweng.log next to the DLL (set up in DllMain now). */
    WwEngInitLogPath();
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
    /* Idempotent: Win32 CreateFileW and NtCreateFile both funnel into
     * this for the same handle (CreateFileW calls NtCreateFile). A
     * second call for an already-tracked handle is a no-op. */
    if (WwEngFindCtx(h)) return;
    /* Only regular files the app can read/write matter. Directories and
     * non-disk handles are skipped by checking the file type. */
    if (GetFileType(h) != FILE_TYPE_DISK) return;
    GetOwnExeName(exe, WWFLT_MAX_EXE_LEN);
    if (!WwEngEvaluatePolicy(exe, lpFileName, &mode, policy_name,
                             WWFLT_MAX_GROUP_LEN)) {
        /* Diagnostic: only log .txt so the log stays readable. */
        {
            size_t n = wcslen(lpFileName);
            if (n >= 4 && _wcsicmp(lpFileName + n - 4, L".txt") == 0) {
                WwEngLog(2, "policy: NO MATCH exe=%ls file=%ls", exe, lpFileName);
            }
        }
        return;
    }
    WwEngLog(2, "policy: MATCH exe=%ls file=%ls mode=%lu policy=%ls",
             exe, lpFileName, mode, policy_name);
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
    /* Diagnostic: log every .txt open so we can see whether the hook
     * fires at all (iat_patched>0 does not prove CreateFileW itself
     * was patched). */
    {
        size_t n = wcslen(lpFileName);
        if (n >= 4 && _wcsicmp(lpFileName + n - 4, L".txt") == 0) {
            WwEngLog(2, "hook: CreateFileW %ls access=0x%lx disp=%lu",
                     lpFileName, dwDesiredAccess, dwCreationDisposition);
        }
    }
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

/* ---- NT hooks (ntdll.dll) ----
 * Same policy/context as the Win32 hooks; the data path is identical
 * except the offset comes from ByteOffset (or the current position
 * when it is NULL) and completion is reported via IO_STATUS_BLOCK. */
static NTSTATUS NTAPI WwHookNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    PWW_OBJECT_ATTRIBUTES ObjectAttributes, PWW_IO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    NTSTATUS st;
    WCHAR win32path[MAX_PATH];
    st = gOrigNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                           AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                           CreateOptions, EaBuffer, EaLength);
    if (!WW_NT_SUCCESS(st) || !FileHandle || *FileHandle == INVALID_HANDLE_VALUE) return st;
    if (!NtPathToWin32(ObjectAttributes ? ObjectAttributes->ObjectName : NULL, win32path, MAX_PATH)) return st;
    /* Diagnostic: log every .txt open so we can see whether the hook
     * fires at all. (The Win32 CreateFileW hook is gone -- it would
     * double-decrypt with NtReadFile -- so NtCreateFile is the log
     * point now.) */
    {
        size_t n = wcslen(win32path);
        if (n >= 4 && _wcsicmp(win32path + n - 4, L".txt") == 0) {
            WwEngLog(2, "hook: NtCreateFile %ls access=0x%lx", win32path, DesiredAccess);
        }
    }
    EnterCriticalSection(&gCtxLock);
    WwEngOnCreate(*FileHandle, win32path, DesiredAccess, 0);
    LeaveCriticalSection(&gCtxLock);
    return st;
}

static NTSTATUS NTAPI WwHookNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    PWW_OBJECT_ATTRIBUTES ObjectAttributes, PWW_IO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions)
{
    NTSTATUS st;
    WCHAR win32path[MAX_PATH];
    st = gOrigNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                         ShareAccess, OpenOptions);
    if (!WW_NT_SUCCESS(st) || !FileHandle || *FileHandle == INVALID_HANDLE_VALUE) return st;
    if (!NtPathToWin32(ObjectAttributes ? ObjectAttributes->ObjectName : NULL, win32path, MAX_PATH)) return st;
    EnterCriticalSection(&gCtxLock);
    WwEngOnCreate(*FileHandle, win32path, DesiredAccess, 0);
    LeaveCriticalSection(&gCtxLock);
    return st;
}

static NTSTATUS NTAPI WwHookNtReadFile(HANDLE FileHandle, HANDLE Event,
    PVOID ApcRoutine, PVOID ApcContext, PWW_IO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
    WW_FILE_CTX *ctx;
    NTSTATUS st;
    LONGLONG phys_off;
    ULONGLONG logical_off;
    ULONG read = 0;

    /* Async I/O passes through, like overlapped I/O in Win32. */
    if (Event || ApcRoutine) {
        return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                               Buffer, Length, ByteOffset, Key);
    }
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(FileHandle);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                               Buffer, Length, ByteOffset, Key);
    }
    if (ByteOffset) {
        phys_off = ByteOffset->QuadPart;
    } else if (!NtGetPosition(FileHandle, &phys_off)) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                               Buffer, Length, ByteOffset, Key);
    }
    if (phys_off < WWFLT_HEADER_SIZE) {
        /* Header read: pass through undecrypted. */
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                               Buffer, Length, ByteOffset, Key);
    }
    logical_off = (ULONGLONG)(phys_off - WWFLT_HEADER_SIZE);
    st = gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                         Buffer, Length, ByteOffset, Key);
    if (WW_NT_SUCCESS(st) && IoStatusBlock && IoStatusBlock->Information > 0) {
        read = (ULONG)IoStatusBlock->Information;
        WwSboxDecrypt(&ctx->sbox, (unsigned char *)Buffer, read, logical_off);
    }
    LeaveCriticalSection(&gCtxLock);
    return st;
}

static NTSTATUS NTAPI WwHookNtWriteFile(HANDLE FileHandle, HANDLE Event,
    PVOID ApcRoutine, PVOID ApcContext, PWW_IO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
    WW_FILE_CTX *ctx;
    NTSTATUS st;
    LONGLONG phys_off;
    ULONGLONG logical_off;
    unsigned char *tmp = NULL;

    if (Event || ApcRoutine) {
        return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                Buffer, Length, ByteOffset, Key);
    }
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(FileHandle);
    if (!ctx || !ctx->is_encrypted || ctx->mode != WWFLT_ENCRYPT_WRITE) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                Buffer, Length, ByteOffset, Key);
    }
    if (ByteOffset) {
        phys_off = ByteOffset->QuadPart;
    } else if (!NtGetPosition(FileHandle, &phys_off)) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                Buffer, Length, ByteOffset, Key);
    }
    if (phys_off < WWFLT_HEADER_SIZE) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                Buffer, Length, ByteOffset, Key);
    }
    logical_off = (ULONGLONG)(phys_off - WWFLT_HEADER_SIZE);
    tmp = (unsigned char *)malloc(Length ? Length : 1);
    if (!tmp) {
        LeaveCriticalSection(&gCtxLock);
        if (IoStatusBlock) { IoStatusBlock->Status = 0xC0000017; IoStatusBlock->Information = 0; }
        return 0xC0000017; /* STATUS_NO_MEMORY */
    }
    memcpy(tmp, Buffer, Length);
    WwSboxEncrypt(&ctx->sbox, tmp, Length, logical_off);
    st = gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                          tmp, Length, ByteOffset, Key);
    free(tmp);
    LeaveCriticalSection(&gCtxLock);
    return st;
}

static NTSTATUS NTAPI WwHookNtClose(HANDLE Handle)
{
    EnterCriticalSection(&gCtxLock);
    WwEngRemoveCtx(Handle);
    LeaveCriticalSection(&gCtxLock);
    return gOrigNtClose(Handle);
}

static NTSTATUS NTAPI WwHookNtSetInformationFile(HANDLE FileHandle,
    PWW_IO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    WW_FILE_INFORMATION_CLASS FileInformationClass)
{
    /* Position and end-of-file are physical offsets already including
     * the header; pass through. Size translation is done in Query. */
    return gOrigNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation,
                                     Length, FileInformationClass);
}

static NTSTATUS NTAPI WwHookNtQueryInformationFile(HANDLE FileHandle,
    PWW_IO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    WW_FILE_INFORMATION_CLASS FileInformationClass)
{
    NTSTATUS st;
    WW_FILE_CTX *ctx;
    st = gOrigNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation,
                                     Length, FileInformationClass);
    if (!WW_NT_SUCCESS(st)) return st;
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(FileHandle);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return st;
    }
    /* Report the LOGICAL size (physical - 512) so callers see the
     * plaintext length. */
    if (FileInformationClass == WW_FileStandardInformation && Length >= sizeof(WW_FILE_STANDARD_INFORMATION)) {
        WW_FILE_STANDARD_INFORMATION *si = (WW_FILE_STANDARD_INFORMATION *)FileInformation;
        if (si->EndOfFile.QuadPart >= WWFLT_HEADER_SIZE)
            si->EndOfFile.QuadPart -= WWFLT_HEADER_SIZE;
        else
            si->EndOfFile.QuadPart = 0;
        if (si->AllocationSize.QuadPart >= WWFLT_HEADER_SIZE)
            si->AllocationSize.QuadPart -= WWFLT_HEADER_SIZE;
    } else if (FileInformationClass == WW_FileEndOfFileInformation && Length >= sizeof(WW_FILE_END_OF_FILE_INFORMATION)) {
        WW_FILE_END_OF_FILE_INFORMATION *ei = (WW_FILE_END_OF_FILE_INFORMATION *)FileInformation;
        if (ei->EndOfFile.QuadPart >= WWFLT_HEADER_SIZE)
            ei->EndOfFile.QuadPart -= WWFLT_HEADER_SIZE;
        else
            ei->EndOfFile.QuadPart = 0;
    }
    LeaveCriticalSection(&gCtxLock);
    return st;
}

/* ---- Detours install ----
 * Patches the function bodies in kernelbase.dll (via kernel32's
 * GetProcAddress, which resolves to the same addresses). DetourAttach
 * rewrites each gOrig* slot to the trampoline, so the hooks above call
 * through to the real function. One transaction for all hooks.
 * No LoadLibrary hook: a function-body patch is process-wide, so
 * modules loaded later call the same patched body automatically.
 * Returns the number of hooks successfully attached. */
/* Attach one hook; record ok/fail in the per-hook status string.
 * `dst` is the address of a gOrig* slot (DetourAttach rewrites it to
 * the trampoline). Returns 1 on success. */
#define WW_ATTACH(dst, hookfn, tag, statusbuf, off) do { \
    LONG _e = NO_ERROR; \
    if (*(dst)) { _e = DetourAttach((PVOID*)(dst), (hookfn)); } \
    if (_e == NO_ERROR && *(dst)) { \
        (statusbuf)[off] = '1'; \
    } else { \
        (statusbuf)[off] = '0'; \
        WwEngLog(1, "attach: %s FAILED err=%ld", (tag), (long)_e); \
    } \
} while (0)

static int WwDetoursInstall(void)
{
    HMODULE ntdll;
    LONG err;
    int n = 0;
    /* Per-hook status, one char per hook in attach order; logged in
     * DllMain so a failed Attach is visible instead of hidden in a
     * total. Order: NtCreateFile, NtOpenFile, NtReadFile, NtWriteFile,
     * NtClose, NtSetInformationFile, NtQueryInformationFile. */
    static char gAttachStatus[8] = "???????";

    /* Win32 originals are resolved for INTERNAL use only
     * (WwEngOnCreate reads/writes the header and queries the size
     * through them). The Win32 hooks are NOT attached -- the data
     * path goes through NtReadFile/NtWriteFile only, so nothing is
     * decrypted or size-translated twice. */
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
        }
    }
    /* NT layer only. The Win32 hooks are NOT attached: Win32
     * ReadFile/WriteFile/CreateFileW call NtReadFile/NtWriteFile/
     * NtCreateFile internally, so hooking both layers would decrypt
     * twice (and translate the size twice). The vendor hooks Nt*
     * only, for the same reason. The Win32 hook functions stay in
     * the source (unused) for reference. */
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        if (!gOrigNtCreateFile) gOrigNtCreateFile = (NtCreateFile_t)GetProcAddress(ntdll, "NtCreateFile");
        if (!gOrigNtOpenFile) gOrigNtOpenFile = (NtOpenFile_t)GetProcAddress(ntdll, "NtOpenFile");
        if (!gOrigNtReadFile) gOrigNtReadFile = (NtReadFile_t)GetProcAddress(ntdll, "NtReadFile");
        if (!gOrigNtWriteFile) gOrigNtWriteFile = (NtWriteFile_t)GetProcAddress(ntdll, "NtWriteFile");
        if (!gOrigNtClose) gOrigNtClose = (NtClose_t)GetProcAddress(ntdll, "NtClose");
        if (!gOrigNtSetInformationFile) gOrigNtSetInformationFile = (NtSetInformationFile_t)GetProcAddress(ntdll, "NtSetInformationFile");
        if (!gOrigNtQueryInformationFile) gOrigNtQueryInformationFile = (NtQueryInformationFile_t)GetProcAddress(ntdll, "NtQueryInformationFile");
    }

    err = DetourTransactionBegin();
    if (err != NO_ERROR) return 0;
    DetourUpdateThread(GetCurrentThread());
    WW_ATTACH(&gOrigNtCreateFile, WwHookNtCreateFile, "NtCreateFile", gAttachStatus, 0);
    WW_ATTACH(&gOrigNtOpenFile, WwHookNtOpenFile, "NtOpenFile", gAttachStatus, 1);
    WW_ATTACH(&gOrigNtReadFile, WwHookNtReadFile, "NtReadFile", gAttachStatus, 2);
    WW_ATTACH(&gOrigNtWriteFile, WwHookNtWriteFile, "NtWriteFile", gAttachStatus, 3);
    WW_ATTACH(&gOrigNtClose, WwHookNtClose, "NtClose", gAttachStatus, 4);
    WW_ATTACH(&gOrigNtSetInformationFile, WwHookNtSetInformationFile, "NtSetInformationFile", gAttachStatus, 5);
    WW_ATTACH(&gOrigNtQueryInformationFile, WwHookNtQueryInformationFile, "NtQueryInformationFile", gAttachStatus, 6);
    err = DetourTransactionCommit();
    if (err != NO_ERROR) {
        DetourTransactionAbort();
        return 0;
    }
    {
        int i;
        for (i = 0; i < 7; i++) if (gAttachStatus[i] == '1') n++;
    }
    /* Keep the status string visible to DllMain's attach log. */
    {
        extern char gWwAttachStatus[8];
        memcpy(gWwAttachStatus, gAttachStatus, 8);
    }
    return n;
}
char gWwAttachStatus[8] = "???????";

/* ---- DllMain ---- */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        gOwnModule = (HMODULE)hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        InitializeCriticalSection(&gCtxLock);
        InitializeCriticalSection(&gPolicyLock);
        /* Eager diagnostics: set up the log path FIRST so the log
         * exists even if no hooked call ever happens, then install
         * the Detours hooks and load the policy eagerly. (Before
         * this, the log was created only lazily from the first
         * hooked call, so a DLL that was injected but whose hooks
         * never fired left no trace at all.) */
        WwEngInitLogPath();
        {
            WCHAR exeName[MAX_PATH];
            int attached;
            extern char gWwAttachStatus[8];
            GetOwnExeName(exeName, MAX_PATH);
            attached = WwDetoursInstall();
            /* Per-hook status (1=ok, 0=fail), order: NtCreateFile,
             * NtOpenFile, NtReadFile, NtWriteFile, NtClose,
             * NtSetInformationFile, NtQueryInformationFile. A total
             * alone hides which Attach failed. */
            WwEngLog(1, "attach: exe=%ls detours_attached=%d status=%s", exeName, attached, gWwAttachStatus);
        }
        WwEngEnsureInit();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        /* Best effort: free contexts. Do not detach the hooks. */
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
