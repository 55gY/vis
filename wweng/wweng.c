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
    WW_FileAllocationInformation = 19,
    WW_FileEndOfFileInformation = 20
} WW_FILE_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, PWW_OBJECT_ATTRIBUTES, PWW_IO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtOpenFile_t)(PHANDLE, ACCESS_MASK, PWW_OBJECT_ATTRIBUTES, PWW_IO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtReadFile_t)(HANDLE, HANDLE, PVOID, PVOID, PWW_IO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *NtWriteFile_t)(HANDLE, HANDLE, PVOID, PVOID, PWW_IO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtSetInformationFile_t)(HANDLE, PWW_IO_STATUS_BLOCK, PVOID, ULONG, WW_FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *NtQueryInformationFile_t)(HANDLE, PWW_IO_STATUS_BLOCK, PVOID, ULONG, WW_FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *NtCreateSection_t)(PHANDLE, ACCESS_MASK, PWW_OBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);
/* Faithful copy of the vendor's hook table (FUN_180034db0):
 * NtDuplicateObject copies the file context to the new handle;
 * NtCopyFileChunk translates both offsets +512; NtWriteFileGather
 * is the scatter version of the write hook. */
typedef NTSTATUS (NTAPI *NtDuplicateObject_t)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtCopyFileChunk_t)(HANDLE, HANDLE, HANDLE, PVOID, PVOID, ULONG, PLARGE_INTEGER, PLARGE_INTEGER, PULONG);
typedef struct _WW_FILE_SEGMENT_ELEMENT {
    PVOID Buffer;
} WW_FILE_SEGMENT_ELEMENT, *PWW_FILE_SEGMENT_ELEMENT;
typedef NTSTATUS (NTAPI *NtWriteFileGather_t)(HANDLE, HANDLE, PVOID, PVOID, PWW_IO_STATUS_BLOCK, PWW_FILE_SEGMENT_ELEMENT, ULONG, PLARGE_INTEGER, PULONG);

static NtCreateFile_t gOrigNtCreateFile = NULL;
static NtOpenFile_t gOrigNtOpenFile = NULL;
static NtReadFile_t gOrigNtReadFile = NULL;
static NtWriteFile_t gOrigNtWriteFile = NULL;
static NtClose_t gOrigNtClose = NULL;
static NtSetInformationFile_t gOrigNtSetInformationFile = NULL;
static NtQueryInformationFile_t gOrigNtQueryInformationFile = NULL;
static NtCreateSection_t gOrigNtCreateSection = NULL;
static NtMapViewOfSection_t gOrigNtMapViewOfSection = NULL;
static NtUnmapViewOfSection_t gOrigNtUnmapViewOfSection = NULL;
static NtDuplicateObject_t gOrigNtDuplicateObject = NULL;
static NtCopyFileChunk_t gOrigNtCopyFileChunk = NULL;
static NtWriteFileGather_t gOrigNtWriteFileGather = NULL;

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

/* Set the file position directly through the original
 * NtSetInformationFile (bypasses our own hook). */
static BOOL NtSetPosition(HANDLE h, PLARGE_INTEGER pos)
{
    WW_IO_STATUS_BLOCK iosb;
    WW_FILE_POSITION_INFORMATION pi;
    NTSTATUS st;
    if (!gOrigNtSetInformationFile) return FALSE;
    pi.CurrentByteOffset = *pos;
    st = gOrigNtSetInformationFile(h, &iosb, &pi, sizeof(pi), WW_FilePositionInformation);
    return WW_NT_SUCCESS(st);
}

/* Physical file size through the ORIGINAL NtQueryInformationFile.
 * MUST bypass our own hook: the hook reports the logical size
 * (physical - 512), so a 514-byte encrypted file looks like 2
 * bytes and OnCreate would dismiss it as "too small for a header".
 * That is exactly what broke the reopen in wwnew-9/10. */
static BOOL NtGetFileSizeRaw(HANDLE h, LONGLONG *size)
{
    WW_IO_STATUS_BLOCK iosb;
    WW_FILE_STANDARD_INFORMATION si;
    NTSTATUS st;
    if (!gOrigNtQueryInformationFile) return FALSE;
    st = gOrigNtQueryInformationFile(h, &iosb, &si, sizeof(si), WW_FileStandardInformation);
    if (!WW_NT_SUCCESS(st)) return FALSE;
    *size = si.EndOfFile.QuadPart;
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

    /* Re-entrancy guard for the probe handle: OnCreate opens a
     * separate read handle via CreateFileW, which funnels back
     * into the NtCreateFile hook and thus into OnCreate. The
     * probe handle is only for reading the header and is closed
     * immediately; it must not get a context and must not open
     * yet another probe handle. */
    static BOOL gWwInProbe = FALSE;

    (void)dwCreationDisposition;
    if (gWwInProbe) return;
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
    /* Size and header probe go through a SEPARATE clean read
     * handle. The caller's handle may be memory-mapped (Notepad
     * maps the file): its reported size then fluctuates (4096 =
     * one mapped page vs the real size) and ReadFile on it fails
     * outright (wweng-10.log: probe read=0 ok=0). A fresh read
     * handle is not mapped and reads reliably. The caller's
     * handle is only used to write a new header and to track
     * the context. If the probe open fails (exclusive lock),
     * fall back to the caller's handle (old behavior). */
    {
        HANDLE probe = INVALID_HANDLE_VALUE;
        LARGE_INTEGER probeSize;
        BOOL haveProbeSize = FALSE;
        DWORD probeErr = 0;
        if (gOrigCreateFileW) {
            /* The probe open re-enters OnCreate via the hooked
             * NtCreateFile; gWwInProbe makes that call a no-op. */
            gWwInProbe = TRUE;
            probe = gOrigCreateFileW(lpFileName, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            gWwInProbe = FALSE;
            if (probe == INVALID_HANDLE_VALUE) probeErr = GetLastError();
        }
        if (probe != INVALID_HANDLE_VALUE) {
            if (gOrigGetFileSizeEx(probe, &probeSize)) {
                haveProbeSize = TRUE;
                fileSize = probeSize;
            } else {
                WwEngLog(2, "create: reopen %ls probe size failed err=%lu", lpFileName, GetLastError());
                gOrigCloseHandle(probe);
                probe = INVALID_HANDLE_VALUE;
            }
        }
        if (!haveProbeSize) {
            /* Fallback: physical size from the caller's handle,
             * bypassing our own Query hook (it reports logical
             * size = physical - 512). */
            if (!NtGetFileSizeRaw(h, &fileSize.QuadPart)) {
                if (probe != INVALID_HANDLE_VALUE) gOrigCloseHandle(probe);
                return;
            }
            WwEngLog(2, "create: reopen %ls probe open failed err=%lu, fallback to handle size=%lld", lpFileName, probeErr, fileSize.QuadPart);
        }
        if (fileSize.QuadPart == 0) {
            /* New (or truncated) file. Only WRITE mode creates a header. */
            char asciiPolicy[WWFLT_MAX_GROUP_LEN];
            DWORD written = 0;
            LARGE_INTEGER zero;
            if (probe != INVALID_HANDLE_VALUE) gOrigCloseHandle(probe);
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
            /* Diagnostic: physical size right after the header
             * write, to pin down the 2.txt-lands-at-8-bytes issue. */
            {
                LONGLONG after = -1;
                NtGetFileSizeRaw(h, &after);
                WwEngLog(2, "create: header written %ls phys_after=%lld", lpFileName, after);
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
            /* Logical view: the caller sees position 0 = content start.
             * The 512-byte header is transparent (the read/write hooks
             * add 512). Seek back to 0, like the vendor does. */
            gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
            WwEngLog(2, "create: new encrypted %ls mode=%lu", lpFileName, mode);
            return;
        }
        if (fileSize.QuadPart < WWFLT_HEADER_SIZE) {
            /* Too small to carry a header: plaintext, no conversion. */
            WwEngLog(2, "create: reopen %ls phys=%lld < 512, no ctx", lpFileName, fileSize.QuadPart);
            if (probe != INVALID_HANDLE_VALUE) gOrigCloseHandle(probe);
            return;
        }
        /* Existing file: probe the first 512 bytes for the magic. */
        {
            LARGE_INTEGER zero;
            zero.QuadPart = 0;
            if (probe != INVALID_HANDLE_VALUE) {
                ok = gOrigReadFile(probe, hdr, WWFLT_HEADER_SIZE, &read, NULL);
                gOrigCloseHandle(probe);
                probe = INVALID_HANDLE_VALUE;
                if (!ok || read != WWFLT_HEADER_SIZE) {
                    WwEngLog(2, "create: reopen %ls phys=%lld probe read=%lu ok=%d err=%lu, no ctx", lpFileName, fileSize.QuadPart, read, ok ? 1 : 0, GetLastError());
                    gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
                    return;
                }
            } else {
                gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
                ok = gOrigReadFile(h, hdr, WWFLT_HEADER_SIZE, &read, NULL);
                if (!ok || read != WWFLT_HEADER_SIZE) {
                    WwEngLog(2, "create: reopen %ls phys=%lld probe read=%lu ok=%d err=%lu, no ctx", lpFileName, fileSize.QuadPart, read, ok ? 1 : 0, GetLastError());
                    gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
                    return;
                }
            }
            if (!WwEngParseHeader(hdr, key, &version)) {
                /* Not an encrypted file: restore position to 0 and pass through. */
                WwEngLog(2, "create: reopen %ls phys=%lld magic mismatch, no ctx", lpFileName, fileSize.QuadPart);
                gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
                return;
            }
            /* Encrypted: seek back to 0. The caller sees a logical view
             * (position 0 = content start); the read/write hooks add 512
             * to reach the physical data. This matches the vendor. */
            gOrigSetFilePointerEx(h, zero, NULL, FILE_BEGIN);
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
            /* Diagnostic: CreateDisposition tells whether an open
             * truncates (CREATE_ALWAYS=2, TRUNCATE_EXISTING=5). */
            WwEngLog(2, "hook: NtCreateFile %ls access=0x%lx disp=%lu", win32path, DesiredAccess, CreateDisposition);
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

/* ---- Async read completion ----
 * The vendor's read hook handles async I/O (it does not just pass
 * it through): an async read that returns undecrypted is exactly
 * how a caller sees garbled content. For an async read we wrap the
 * caller's APC: when the real read completes, our wrapper decrypts
 * the buffer (counter = the logical offset) and then invokes the
 * original APC. If only an Event was given (no APC), there is
 * nothing to run on completion, so the read is done synchronously
 * in the hook, decrypted, and the Event is signaled by us. */
typedef struct _WW_ASYNC_READ_CTX {
    WW_SBOX_CTX sbox;
    PVOID buffer;
    ULONG length;
    ULONGLONG logical_off;
    PVOID orig_apc;
    PVOID orig_apc_ctx;
} WW_ASYNC_READ_CTX;

typedef VOID (NTAPI *WW_APC_ROUTINE)(PVOID ApcContext, PWW_IO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

static VOID NTAPI WwReadApc(PVOID ApcContext, PWW_IO_STATUS_BLOCK IoStatusBlock, ULONG Reserved)
{
    WW_ASYNC_READ_CTX *actx = (WW_ASYNC_READ_CTX *)ApcContext;
    WW_APC_ROUTINE orig;
    PVOID orig_ctx;
    (void)Reserved;
    if (actx) {
        if (IoStatusBlock && IoStatusBlock->Information > 0) {
            WwSboxDecrypt(&actx->sbox, (unsigned char *)actx->buffer,
                          (ULONG)IoStatusBlock->Information, actx->logical_off);
            WwEngLog(2, "ntread: async hbuf=%p logical=%llu bytes=%llu",
                     actx->buffer, actx->logical_off,
                     (unsigned long long)IoStatusBlock->Information);
        }
        orig = (WW_APC_ROUTINE)actx->orig_apc;
        orig_ctx = actx->orig_apc_ctx;
        free(actx);
        if (orig) orig(orig_ctx, IoStatusBlock, Reserved);
    }
}

static NTSTATUS NTAPI WwHookNtReadFile(HANDLE FileHandle, HANDLE Event,
    PVOID ApcRoutine, PVOID ApcContext, PWW_IO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
    WW_FILE_CTX *ctx;
    NTSTATUS st;
    LONGLONG logical_off;
    ULONG read = 0;
    BOOL use_explicit_off = FALSE;
    LARGE_INTEGER saved_off;
    BOOL is_async = (Event != NULL || ApcRoutine != NULL);

    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(FileHandle);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                               Buffer, Length, ByteOffset, Key);
    }
    /* The caller works in a LOGICAL view (0 = content start, the
     * 512-byte header is invisible). Translate to physical by
     * adding 512, exactly like the vendor's read hook: it rewrites
     * ByteOffset in place (+0x200), or moves the file position
     * (+0x200) and restores it afterwards. */
    if (ByteOffset) {
        logical_off = ByteOffset->QuadPart;
        if (logical_off < 0) {
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                   Buffer, Length, ByteOffset, Key);
        }
        use_explicit_off = TRUE;
        saved_off.QuadPart = logical_off;
        ByteOffset->QuadPart = logical_off + WWFLT_HEADER_SIZE;
    } else {
        if (!NtGetPosition(FileHandle, &logical_off)) {
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                   Buffer, Length, ByteOffset, Key);
        }
        if (logical_off < 0) {
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                   Buffer, Length, ByteOffset, Key);
        }
        saved_off.QuadPart = logical_off;
        {
            LARGE_INTEGER phys;
            phys.QuadPart = logical_off + WWFLT_HEADER_SIZE;
            if (!NtSetPosition(FileHandle, &phys)) {
                LeaveCriticalSection(&gCtxLock);
                return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                       Buffer, Length, ByteOffset, Key);
            }
        }
    }
    if (is_async && ApcRoutine) {
        /* Wrap the caller's APC so the buffer is decrypted when the
         * real read completes. The kernel still signals Event. */
        WW_ASYNC_READ_CTX *actx = (WW_ASYNC_READ_CTX *)malloc(sizeof(WW_ASYNC_READ_CTX));
        if (!actx) {
            /* Out of memory: fall back to a synchronous read. */
            if (use_explicit_off) ByteOffset->QuadPart = saved_off.QuadPart;
            else NtSetPosition(FileHandle, &saved_off);
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                   Buffer, Length, ByteOffset, Key);
        }
        actx->sbox = ctx->sbox;
        actx->buffer = Buffer;
        actx->length = Length;
        actx->logical_off = (ULONGLONG)logical_off;
        actx->orig_apc = ApcRoutine;
        actx->orig_apc_ctx = ApcContext;
        st = gOrigNtReadFile(FileHandle, Event, (PVOID)WwReadApc, (PVOID)actx,
                             IoStatusBlock, Buffer, Length, ByteOffset, Key);
        /* Restore the caller's logical view. */
        if (use_explicit_off) {
            ByteOffset->QuadPart = saved_off.QuadPart;
        } else if (WW_NT_SUCCESS(st) && st != 0x103 /* STATUS_PENDING */) {
            /* Completed synchronously: restore position now. If it is
             * pending, the position was already advanced by the
             * kernel; the APC runs after completion and the caller
             * observes the logical position via our Query hook. */
            LARGE_INTEGER cur;
            cur.QuadPart = saved_off.QuadPart + (LONGLONG)(IoStatusBlock ? (LONGLONG)IoStatusBlock->Information : 0);
            NtSetPosition(FileHandle, &cur);
        }
        LeaveCriticalSection(&gCtxLock);
        return st;
    }
    if (is_async) {
        /* Event only, no APC: do the read synchronously, decrypt,
         * signal the Event ourselves. The caller waits on the Event
         * and then sees decrypted data. */
        st = gOrigNtReadFile(FileHandle, NULL, NULL, NULL, IoStatusBlock,
                             Buffer, Length, ByteOffset, Key);
        if (WW_NT_SUCCESS(st) && IoStatusBlock && IoStatusBlock->Information > 0) {
            read = (ULONG)IoStatusBlock->Information;
            WwSboxDecrypt(&ctx->sbox, (unsigned char *)Buffer, read, (ULONGLONG)logical_off);
            WwEngLog(2, "ntread: h=%p logical=%lld bytes=%lu (event-sync)", FileHandle, logical_off, read);
        }
        if (use_explicit_off) {
            ByteOffset->QuadPart = saved_off.QuadPart;
        } else if (WW_NT_SUCCESS(st) && IoStatusBlock) {
            LARGE_INTEGER cur;
            cur.QuadPart = saved_off.QuadPart + (LONGLONG)read;
            NtSetPosition(FileHandle, &cur);
        }
        if (Event) SetEvent(Event);
        LeaveCriticalSection(&gCtxLock);
        return st;
    }
    st = gOrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                         Buffer, Length, ByteOffset, Key);
    if (WW_NT_SUCCESS(st) && IoStatusBlock && IoStatusBlock->Information > 0) {
        read = (ULONG)IoStatusBlock->Information;
        WwSboxDecrypt(&ctx->sbox, (unsigned char *)Buffer, read, (ULONGLONG)logical_off);
        WwEngLog(2, "ntread: h=%p logical=%lld bytes=%lu", FileHandle, logical_off, read);
    }
    /* Restore the caller's logical view of the position. */
    if (use_explicit_off) {
        ByteOffset->QuadPart = saved_off.QuadPart;
    } else if (WW_NT_SUCCESS(st) && IoStatusBlock) {
        LARGE_INTEGER cur;
        cur.QuadPart = saved_off.QuadPart + (LONGLONG)read;
        NtSetPosition(FileHandle, &cur);
    }
    LeaveCriticalSection(&gCtxLock);
    return st;
}

/* ---- Async write completion ----
 * Like the read path: an async write must carry an encrypted copy
 * that stays alive until the kernel is done with it. Wrap the
 * caller's APC to free the copy and invoke the original APC. With
 * only an Event, do the write synchronously and signal the Event. */
typedef struct _WW_ASYNC_WRITE_CTX {
    unsigned char *tmp;
    PVOID orig_apc;
    PVOID orig_apc_ctx;
} WW_ASYNC_WRITE_CTX;

static VOID NTAPI WwWriteApc(PVOID ApcContext, PWW_IO_STATUS_BLOCK IoStatusBlock, ULONG Reserved)
{
    WW_ASYNC_WRITE_CTX *actx = (WW_ASYNC_WRITE_CTX *)ApcContext;
    WW_APC_ROUTINE orig;
    PVOID orig_ctx;
    (void)Reserved;
    if (actx) {
        free(actx->tmp);
        orig = (WW_APC_ROUTINE)actx->orig_apc;
        orig_ctx = actx->orig_apc_ctx;
        free(actx);
        if (orig) orig(orig_ctx, IoStatusBlock, Reserved);
    }
}

static NTSTATUS NTAPI WwHookNtWriteFile(HANDLE FileHandle, HANDLE Event,
    PVOID ApcRoutine, PVOID ApcContext, PWW_IO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
    WW_FILE_CTX *ctx;
    NTSTATUS st;
    LONGLONG logical_off;
    unsigned char *tmp = NULL;
    BOOL use_explicit_off = FALSE;
    LARGE_INTEGER saved_off;
    ULONG written = 0;
    BOOL is_async = (Event != NULL || ApcRoutine != NULL);

    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(FileHandle);
    if (!ctx || !ctx->is_encrypted || ctx->mode != WWFLT_ENCRYPT_WRITE) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                Buffer, Length, ByteOffset, Key);
    }
    /* Logical view, like the read hook: add 512 to reach the physical
     * data, encrypt with the logical offset as counter. */
    if (ByteOffset) {
        logical_off = ByteOffset->QuadPart;
        if (logical_off < 0) {
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                    Buffer, Length, ByteOffset, Key);
        }
        use_explicit_off = TRUE;
        saved_off.QuadPart = logical_off;
        ByteOffset->QuadPart = logical_off + WWFLT_HEADER_SIZE;
    } else {
        if (!NtGetPosition(FileHandle, &logical_off) || logical_off < 0) {
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                    Buffer, Length, ByteOffset, Key);
        }
        saved_off.QuadPart = logical_off;
        {
            LARGE_INTEGER phys;
            phys.QuadPart = logical_off + WWFLT_HEADER_SIZE;
            if (!NtSetPosition(FileHandle, &phys)) {
                LeaveCriticalSection(&gCtxLock);
                return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                        Buffer, Length, ByteOffset, Key);
            }
        }
    }
    tmp = (unsigned char *)malloc(Length ? Length : 1);
    if (!tmp) {
        if (use_explicit_off) ByteOffset->QuadPart = saved_off.QuadPart;
        else NtSetPosition(FileHandle, &saved_off);
        LeaveCriticalSection(&gCtxLock);
        if (IoStatusBlock) { IoStatusBlock->Status = 0xC0000017; IoStatusBlock->Information = 0; }
        return 0xC0000017; /* STATUS_NO_MEMORY */
    }
    memcpy(tmp, Buffer, Length);
    WwSboxEncrypt(&ctx->sbox, tmp, Length, (ULONGLONG)logical_off);
    WwEngLog(2, "ntwrite: h=%p logical=%lld len=%lu expl=%d async=%d", FileHandle, logical_off, Length, use_explicit_off ? 1 : 0, is_async ? 1 : 0);
    if (is_async && ApcRoutine) {
        WW_ASYNC_WRITE_CTX *actx = (WW_ASYNC_WRITE_CTX *)malloc(sizeof(WW_ASYNC_WRITE_CTX));
        if (!actx) {
            free(tmp);
            if (use_explicit_off) ByteOffset->QuadPart = saved_off.QuadPart;
            else NtSetPosition(FileHandle, &saved_off);
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                    Buffer, Length, ByteOffset, Key);
        }
        actx->tmp = tmp;
        actx->orig_apc = ApcRoutine;
        actx->orig_apc_ctx = ApcContext;
        st = gOrigNtWriteFile(FileHandle, Event, (PVOID)WwWriteApc, (PVOID)actx,
                              IoStatusBlock, tmp, Length, ByteOffset, Key);
        if (use_explicit_off) {
            ByteOffset->QuadPart = saved_off.QuadPart;
        } else if (WW_NT_SUCCESS(st) && st != 0x103 /* STATUS_PENDING */ && IoStatusBlock) {
            LARGE_INTEGER cur;
            written = (ULONG)IoStatusBlock->Information;
            cur.QuadPart = saved_off.QuadPart + (LONGLONG)written;
            NtSetPosition(FileHandle, &cur);
        }
        LeaveCriticalSection(&gCtxLock);
        return st;
    }
    if (is_async) {
        /* Event only: synchronous write, then signal the Event. */
        st = gOrigNtWriteFile(FileHandle, NULL, NULL, NULL, IoStatusBlock,
                              tmp, Length, ByteOffset, Key);
        free(tmp);
        if (WW_NT_SUCCESS(st) && IoStatusBlock) {
            WwEngLog(2, "ntwrite: h=%p done written=%llu (event-sync)", FileHandle,
                     (unsigned long long)IoStatusBlock->Information);
        }
        if (use_explicit_off) {
            ByteOffset->QuadPart = saved_off.QuadPart;
        } else if (WW_NT_SUCCESS(st) && IoStatusBlock) {
            LARGE_INTEGER cur;
            written = (ULONG)IoStatusBlock->Information;
            cur.QuadPart = saved_off.QuadPart + (LONGLONG)written;
            NtSetPosition(FileHandle, &cur);
        }
        if (Event) SetEvent(Event);
        LeaveCriticalSection(&gCtxLock);
        return st;
    }
    st = gOrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                          tmp, Length, ByteOffset, Key);
    free(tmp);
    if (WW_NT_SUCCESS(st) && IoStatusBlock) {
        WwEngLog(2, "ntwrite: h=%p done written=%llu", FileHandle,
                 (unsigned long long)IoStatusBlock->Information);
    }
    if (use_explicit_off) {
        ByteOffset->QuadPart = saved_off.QuadPart;
    } else if (WW_NT_SUCCESS(st) && IoStatusBlock) {
        LARGE_INTEGER cur;
        written = (ULONG)IoStatusBlock->Information;
        cur.QuadPart = saved_off.QuadPart + (LONGLONG)written;
        NtSetPosition(FileHandle, &cur);
    }
    LeaveCriticalSection(&gCtxLock);
    return st;
}

static NTSTATUS NTAPI WwHookNtClose(HANDLE Handle)
{
    EnterCriticalSection(&gCtxLock);
    {
        /* Diagnostic: physical size at close, to catch the 2.txt
         * 513 -> 8 truncation window. */
        WW_FILE_CTX *ctx = WwEngFindCtx(Handle);
        if (ctx && ctx->is_encrypted) {
            LONGLONG sz = -1;
            NtGetFileSizeRaw(Handle, &sz);
            WwEngLog(2, "ntclose: h=%p phys=%lld", Handle, sz);
        }
    }
    WwEngRemoveCtx(Handle);
    LeaveCriticalSection(&gCtxLock);
    return gOrigNtClose(Handle);
}

/* ---- NtDuplicateObject (vendor FUN_18002d7d0) ----
 * When a handle is duplicated, the new handle gets a full copy of
 * the source handle's file context (same sbox/key/mode). Without
 * this, a duplicated handle has no context and its reads/writes
 * bypass the encryption (or get mis-translated). */
static NTSTATUS NTAPI WwHookNtDuplicateObject(HANDLE SourceProcessHandle,
    HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options)
{
    NTSTATUS st;
    WW_FILE_CTX *src = NULL;
    WW_FILE_CTX saved;
    BOOL have_src = FALSE;

    EnterCriticalSection(&gCtxLock);
    src = WwEngFindCtx(SourceHandle);
    if (src && src->is_encrypted) {
        saved = *src;  /* copy the whole context (sbox/key/mode) */
        have_src = TRUE;
    }
    LeaveCriticalSection(&gCtxLock);

    st = gOrigNtDuplicateObject(SourceProcessHandle, SourceHandle,
                                TargetProcessHandle, TargetHandle,
                                DesiredAccess, Attributes, Options);
    if (!WW_NT_SUCCESS(st) || !TargetHandle || !*TargetHandle) return st;
    if (!have_src) return st;
    /* Only duplicate within the same process (cross-process handles
     * belong to another process's table and we cannot track them). */
    if (TargetProcessHandle != (HANDLE)(LONG_PTR)-1 &&
        TargetProcessHandle != GetCurrentProcess()) {
        return st;
    }
    EnterCriticalSection(&gCtxLock);
    {
        WW_FILE_CTX *nctx = (WW_FILE_CTX *)calloc(1, sizeof(WW_FILE_CTX));
        if (nctx) {
            *nctx = saved;
            nctx->hFile = *TargetHandle;
            nctx->next = NULL;
            WwEngInsertCtx(nctx);
            WwEngLog(2, "ntdup: h=%p -> h=%p", SourceHandle, *TargetHandle);
        }
    }
    LeaveCriticalSection(&gCtxLock);
    return st;
}

/* ---- NtCopyFileChunk (vendor FUN_180033410) ----
 * Server-side copy: both the source and the destination offsets
 * are logical, so both are translated +512. If the copy covers
 * the whole file (both offsets 0) the destination inherits the
 * source's context (same key), so a copied file stays encrypted
 * and readable. */
static NTSTATUS NTAPI WwHookNtCopyFileChunk(HANDLE SourceHandle,
    HANDLE DestHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    ULONG Length, PLARGE_INTEGER SourceOffset, PLARGE_INTEGER DestOffset,
    PULONG Key)
{
    NTSTATUS st;
    WW_FILE_CTX *src = NULL;
    WW_FILE_CTX *dst = NULL;
    LARGE_INTEGER saved_src, saved_dst;
    BOOL have_src_off = FALSE, have_dst_off = FALSE;

    EnterCriticalSection(&gCtxLock);
    src = WwEngFindCtx(SourceHandle);
    dst = WwEngFindCtx(DestHandle);
    if (src && src->is_encrypted && SourceOffset) {
        saved_src.QuadPart = SourceOffset->QuadPart;
        SourceOffset->QuadPart = saved_src.QuadPart + WWFLT_HEADER_SIZE;
        have_src_off = TRUE;
    }
    if (dst && dst->is_encrypted && DestOffset) {
        saved_dst.QuadPart = DestOffset->QuadPart;
        DestOffset->QuadPart = saved_dst.QuadPart + WWFLT_HEADER_SIZE;
        have_dst_off = TRUE;
    }
    LeaveCriticalSection(&gCtxLock);

    st = gOrigNtCopyFileChunk(SourceHandle, DestHandle, Event, ApcRoutine,
                              ApcContext, Length, SourceOffset, DestOffset, Key);

    if (have_src_off) SourceOffset->QuadPart = saved_src.QuadPart;
    if (have_dst_off) DestOffset->QuadPart = saved_dst.QuadPart;

    /* Whole-file copy (both offsets 0): sync the destination's
     * context with the source's, like the vendor does. */
    if (WW_NT_SUCCESS(st) && src && src->is_encrypted &&
        (!SourceOffset || SourceOffset->QuadPart == 0) &&
        (!DestOffset || DestOffset->QuadPart == 0)) {
        EnterCriticalSection(&gCtxLock);
        if (!WwEngFindCtx(DestHandle)) {
            WW_FILE_CTX *nctx = (WW_FILE_CTX *)calloc(1, sizeof(WW_FILE_CTX));
            if (nctx) {
                *nctx = *src;
                nctx->hFile = DestHandle;
                nctx->next = NULL;
                WwEngInsertCtx(nctx);
            }
        }
        LeaveCriticalSection(&gCtxLock);
    }
    return st;
}

/* ---- NtWriteFileGather (vendor FUN_18002a1c0) ----
 * The scatter version of the write hook: same offset translation
 * (+512) and encryption, applied per segment. Each segment is a
 * page (4096 bytes) except possibly the last. The data is
 * encrypted into temp buffers (never in place, so the caller's
 * buffers are untouched), exactly like the vendor encrypts into
 * its own pool buffers. */
static NTSTATUS NTAPI WwHookNtWriteFileGather(HANDLE FileHandle,
    HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PWW_IO_STATUS_BLOCK IoStatusBlock, PWW_FILE_SEGMENT_ELEMENT SegmentArray,
    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
    WW_FILE_CTX *ctx;
    NTSTATUS st;
    LONGLONG logical_off;
    BOOL use_explicit_off = FALSE;
    LARGE_INTEGER saved_off;
    ULONG nseg, i;
    PWW_FILE_SEGMENT_ELEMENT tmp_segs = NULL;
    unsigned char **tmp_bufs = NULL;

    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(FileHandle);
    if (!ctx || !ctx->is_encrypted || ctx->mode != WWFLT_ENCRYPT_WRITE) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtWriteFileGather(FileHandle, Event, ApcRoutine, ApcContext,
                                      IoStatusBlock, SegmentArray, Length,
                                      ByteOffset, Key);
    }
    if (ByteOffset) {
        logical_off = ByteOffset->QuadPart;
        if (logical_off < 0) {
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtWriteFileGather(FileHandle, Event, ApcRoutine, ApcContext,
                                          IoStatusBlock, SegmentArray, Length,
                                          ByteOffset, Key);
        }
        use_explicit_off = TRUE;
        saved_off.QuadPart = logical_off;
        ByteOffset->QuadPart = logical_off + WWFLT_HEADER_SIZE;
    } else {
        if (!NtGetPosition(FileHandle, &logical_off) || logical_off < 0) {
            LeaveCriticalSection(&gCtxLock);
            return gOrigNtWriteFileGather(FileHandle, Event, ApcRoutine, ApcContext,
                                          IoStatusBlock, SegmentArray, Length,
                                          ByteOffset, Key);
        }
        saved_off.QuadPart = logical_off;
        {
            LARGE_INTEGER phys;
            phys.QuadPart = logical_off + WWFLT_HEADER_SIZE;
            if (!NtSetPosition(FileHandle, &phys)) {
                LeaveCriticalSection(&gCtxLock);
                return gOrigNtWriteFileGather(FileHandle, Event, ApcRoutine, ApcContext,
                                              IoStatusBlock, SegmentArray, Length,
                                              ByteOffset, Key);
            }
        }
    }
    nseg = (Length + 4095) / 4096;
    tmp_segs = (PWW_FILE_SEGMENT_ELEMENT)malloc(nseg * sizeof(WW_FILE_SEGMENT_ELEMENT));
    tmp_bufs = (unsigned char **)malloc(nseg * sizeof(unsigned char *));
    if (!tmp_segs || !tmp_bufs) {
        free(tmp_segs);
        free(tmp_bufs);
        if (use_explicit_off) ByteOffset->QuadPart = saved_off.QuadPart;
        else NtSetPosition(FileHandle, &saved_off);
        LeaveCriticalSection(&gCtxLock);
        if (IoStatusBlock) { IoStatusBlock->Status = 0xC0000017; IoStatusBlock->Information = 0; }
        return 0xC0000017;
    }
    for (i = 0; i < nseg; i++) tmp_bufs[i] = NULL;
    for (i = 0; i < nseg; i++) {
        ULONG seglen = Length - i * 4096;
        if (seglen > 4096) seglen = 4096;
        tmp_bufs[i] = (unsigned char *)malloc(seglen ? seglen : 1);
        if (!tmp_bufs[i]) break;
        memcpy(tmp_bufs[i], SegmentArray[i].Buffer, seglen);
        WwSboxEncrypt(&ctx->sbox, tmp_bufs[i], seglen,
                      (ULONGLONG)(logical_off + (LONGLONG)i * 4096));
        tmp_segs[i].Buffer = tmp_bufs[i];
    }
    if (i != nseg) {
        ULONG j;
        for (j = 0; j < i; j++) free(tmp_bufs[j]);
        free(tmp_bufs);
        free(tmp_segs);
        if (use_explicit_off) ByteOffset->QuadPart = saved_off.QuadPart;
        else NtSetPosition(FileHandle, &saved_off);
        LeaveCriticalSection(&gCtxLock);
        if (IoStatusBlock) { IoStatusBlock->Status = 0xC0000017; IoStatusBlock->Information = 0; }
        return 0xC0000017;
    }
    WwEngLog(2, "ntwritegather: h=%p logical=%lld len=%lu expl=%d", FileHandle, logical_off, Length, use_explicit_off ? 1 : 0);
    st = gOrigNtWriteFileGather(FileHandle, Event, ApcRoutine, ApcContext,
                                IoStatusBlock, tmp_segs, Length, ByteOffset, Key);
    {
        ULONG j;
        for (j = 0; j < nseg; j++) free(tmp_bufs[j]);
        free(tmp_bufs);
        free(tmp_segs);
    }
    if (use_explicit_off) {
        ByteOffset->QuadPart = saved_off.QuadPart;
    } else if (WW_NT_SUCCESS(st) && IoStatusBlock) {
        LARGE_INTEGER cur;
        cur.QuadPart = saved_off.QuadPart + (LONGLONG)IoStatusBlock->Information;
        NtSetPosition(FileHandle, &cur);
    }
    LeaveCriticalSection(&gCtxLock);
    return st;
}

/* ---- Memory-mapped reads ----
 * A reader that maps the file (Notepad does this) never calls
 * NtReadFile, so the read hook never sees the content. The vendor
 * handles this in its NtCreateSection hook (FUN_18002a870 ->
 * FUN_18002a6a0): it builds the section, maps it, decrypts the
 * mapped view in place, then unmaps. We do the safer equivalent:
 * for an encrypted file, read the content, decrypt it, and hand
 * the caller an anonymous (pagefile-backed) section holding the
 * plaintext. The caller maps it and sees plaintext; writes to
 * the mapping do not touch the encrypted file on disk (a
 * limitation: mapped writes are not written back -- Notepad
 * saves through NtWriteFile, which is hooked, so this is fine
 * for the target apps). SEC_IMAGE sections and anonymous sections
 * pass through untouched. */
static NTSTATUS NTAPI WwHookNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PWW_OBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
    WW_FILE_CTX *ctx;
    NTSTATUS st;
    LONGLONG phys_size = 0;
    LONGLONG logical_size = 0;
    unsigned char *buf = NULL;
    HANDLE anon = NULL;
    LARGE_INTEGER maxsz;
    PVOID base = NULL;
    SIZE_T viewsz = 0;
    LARGE_INTEGER secoff;

    if (!FileHandle) {
        return gOrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                    MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }
    /* SEC_IMAGE = an executable image being loaded: never touch. */
    if (AllocationAttributes & 0x1000000 /* SEC_IMAGE */) {
        return gOrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                    MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(FileHandle);
    if (!ctx || !ctx->is_encrypted) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                    MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }
    /* Physical size, then logical = physical - 512. */
    if (!NtGetFileSizeRaw(FileHandle, &phys_size) || phys_size < WWFLT_HEADER_SIZE) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                    MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }
    logical_size = phys_size - WWFLT_HEADER_SIZE;
    if (logical_size <= 0) {
        logical_size = 0;
    }
    /* Read the ciphertext (physical, offset 512) and decrypt it.
     * Faithful copy of the vendor's FUN_18002a440: read in chunks
     * from the physical offset, decrypt each chunk with the
     * LOGICAL offset as counter, and lay the plaintext
     * contiguously into the destination starting at offset 0. */
    buf = (unsigned char *)malloc((size_t)(logical_size > 0 ? logical_size : 1));
    if (!buf) {
        LeaveCriticalSection(&gCtxLock);
        return gOrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                    MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }
    if (logical_size > 0) {
        /* Chunked fill, like the vendor (8KB temp buffer). */
        LONGLONG phys_off = WWFLT_HEADER_SIZE;  /* physical offset */
        LONGLONG done = 0;                      /* logical bytes filled */
        while (done < logical_size) {
            ULONG chunk = (ULONG)(logical_size - done);
            WW_IO_STATUS_BLOCK iosb;
            LARGE_INTEGER off;
            if (chunk > 8192) chunk = 8192;
            off.QuadPart = phys_off;
            st = gOrigNtReadFile(FileHandle, NULL, NULL, NULL, &iosb,
                                 buf + done, chunk, &off, NULL);
            if (!WW_NT_SUCCESS(st) || iosb.Information == 0) {
                free(buf);
                LeaveCriticalSection(&gCtxLock);
                return gOrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                            MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
            }
            WwSboxDecrypt(&ctx->sbox, buf + done, (size_t)iosb.Information,
                          (ULONGLONG)done);
            done += (LONGLONG)iosb.Information;
            phys_off += (LONGLONG)iosb.Information;
        }
        /* Diagnostic: first bytes of the decrypted content, so a
         * wrong key/sbox shows up immediately in the log. */
        {
            char hex[65];
            size_t k, n = (size_t)logical_size < 16 ? (size_t)logical_size : 16;
            for (k = 0; k < n; k++) {
                hex[k * 2] = "0123456789abcdef"[buf[k] >> 4];
                hex[k * 2 + 1] = "0123456789abcdef"[buf[k] & 0xf];
            }
            hex[n * 2] = '\0';
            WwEngLog(2, "ntsection: h=%p logical=%lld plain_hex=%s", FileHandle, logical_size, hex);
        }
    } else {
        WwEngLog(2, "ntsection: h=%p logical=%lld (mapped read)", FileHandle, logical_size);
    }
    LeaveCriticalSection(&gCtxLock);
    /* Anonymous section holding the plaintext. PAGE_READWRITE so we
     * can copy the data in; the caller may map it read-only.
     * Faithful copy of the vendor's FUN_18002a6a0: MaximumSize is
     * the PHYSICAL file size (not the logical size), DesiredAccess
     * is SECTION_ALL_ACCESS (0xf001f), protection PAGE_READWRITE,
     * SEC_COMMIT. The plaintext is laid at view offset 0; the
     * rest of the (physical-sized) section stays zero. */
    maxsz.QuadPart = phys_size;
    st = gOrigNtCreateSection(&anon, 0xf001f /* SECTION_ALL_ACCESS */, ObjectAttributes, &maxsz,
                              0x04 /* PAGE_READWRITE */, 0x08000000 /* SEC_COMMIT */, NULL);
    if (!WW_NT_SUCCESS(st) || !anon) {
        WwEngLog(1, "ntsection: anon create failed st=0x%lx", (unsigned long)st);
        free(buf);
        return gOrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                    MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }
    if (logical_size > 0) {
        viewsz = (SIZE_T)logical_size;
        secoff.QuadPart = 0;
        st = gOrigNtMapViewOfSection(anon, (HANDLE)(LONG_PTR)-1 /* NtCurrentProcess */,
                                     &base, 0, 0, &secoff, &viewsz, 1 /* ViewShare */, 0, 0x04 /* PAGE_READWRITE */);
        if (!WW_NT_SUCCESS(st) || !base) {
            WwEngLog(1, "ntsection: anon map failed st=0x%lx", (unsigned long)st);
            gOrigNtClose(anon);
            free(buf);
            return gOrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                        MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
        }
        memcpy(base, buf, (size_t)logical_size);
        gOrigNtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, base);
    }
    free(buf);
    *SectionHandle = anon;
    WwEngLog(2, "ntsection: h=%p anon section ok", FileHandle);
    return 0; /* STATUS_SUCCESS */
}

static NTSTATUS NTAPI WwHookNtSetInformationFile(HANDLE FileHandle,
    PWW_IO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    WW_FILE_INFORMATION_CLASS FileInformationClass)
{
    WW_FILE_CTX *ctx;
    /* The raw file position is kept in the LOGICAL view (0 = content
     * start); the read/write hooks add 512 themselves for the I/O
     * and restore it. So a seek passes through untranslated. Only
     * a truncate (EndOfFile) needs +512, because the physical file
     * is 512 bytes longer than the logical content. */
    EnterCriticalSection(&gCtxLock);
    ctx = WwEngFindCtx(FileHandle);
    /* Diagnostic: log every size-changing SetInformationFile call
     * (EndOfFile=20, Allocation=19), with or without a context,
     * so a truncate on a context-less handle -- which passes
     * through untranslated -- shows up. */
    if ((FileInformationClass == WW_FileEndOfFileInformation ||
         FileInformationClass == WW_FileAllocationInformation) && Length >= 8) {
        LONGLONG v = *(LONGLONG *)FileInformation;
        WwEngLog(2, "ntset: h=%p class=%d val=%lld ctx=%d", FileHandle,
                 (int)FileInformationClass, v, ctx ? 1 : 0);
    }
    /* Faithful copy of the vendor's FUN_18002bfc0: BOTH the
     * EndOfFile (20) and the AllocationSize (19) are translated
     * +512, because the physical file is 512 bytes longer than
     * the logical content. Missing the Allocation translation
     * is what truncated 2.txt: Notepad sets EOF=1 (translated
     * to 513) and Allocation=1 (left at 1), and the filesystem
     * then truncates the file to the 1-byte allocation -- the
     * 8-byte remnant is the first 8 bytes of the header.
     * After the real call the caller's buffer is restored
     * (-512), exactly like the vendor. */
    if (ctx && ctx->is_encrypted) {
        if ((FileInformationClass == WW_FileEndOfFileInformation ||
             FileInformationClass == WW_FileAllocationInformation) &&
            Length >= sizeof(LARGE_INTEGER)) {
            LARGE_INTEGER *sz = (LARGE_INTEGER *)FileInformation;
            if (sz->QuadPart >= 0)
                sz->QuadPart += WWFLT_HEADER_SIZE;
        } else if (FileInformationClass == WW_FilePositionInformation && Length >= sizeof(WW_FILE_POSITION_INFORMATION)) {
            WW_FILE_POSITION_INFORMATION *pi = (WW_FILE_POSITION_INFORMATION *)FileInformation;
            WwEngLog(2, "ntset: h=%p class=Position val=%lld",
                     FileHandle, pi->CurrentByteOffset.QuadPart);
        }
    }
    LeaveCriticalSection(&gCtxLock);
    {
        NTSTATUS st = gOrigNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation,
                                                Length, FileInformationClass);
        /* Restore the caller's buffer (vendor does this too). */
        if (ctx && ctx->is_encrypted &&
            (FileInformationClass == WW_FileEndOfFileInformation ||
             FileInformationClass == WW_FileAllocationInformation) &&
            Length >= sizeof(LARGE_INTEGER)) {
            LARGE_INTEGER *sz = (LARGE_INTEGER *)FileInformation;
            if (sz->QuadPart >= WWFLT_HEADER_SIZE)
                sz->QuadPart -= WWFLT_HEADER_SIZE;
        }
        return st;
    }
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
     * plaintext length. The file position is already logical (the
     * raw position is maintained in the logical view), so it is
     * reported as-is.
     * Faithful copy of the vendor's FUN_18002bdb0: for
     * FileStandardInformation only the EndOfFile is adjusted
     * (-512); the AllocationSize is left as the physical value.
     * (An earlier version subtracted 512 from both; the vendor
     * does not touch AllocationSize here.) */
    if (FileInformationClass == WW_FileStandardInformation && Length >= sizeof(WW_FILE_STANDARD_INFORMATION)) {
        WW_FILE_STANDARD_INFORMATION *si = (WW_FILE_STANDARD_INFORMATION *)FileInformation;
        if (si->EndOfFile.QuadPart >= WWFLT_HEADER_SIZE)
            si->EndOfFile.QuadPart -= WWFLT_HEADER_SIZE;
        else
            si->EndOfFile.QuadPart = 0;
    } else if (FileInformationClass == WW_FileEndOfFileInformation && Length >= sizeof(WW_FILE_END_OF_FILE_INFORMATION)) {
        WW_FILE_END_OF_FILE_INFORMATION *ei = (WW_FILE_END_OF_FILE_INFORMATION *)FileInformation;
        if (ei->EndOfFile.QuadPart >= WWFLT_HEADER_SIZE)
            ei->EndOfFile.QuadPart -= WWFLT_HEADER_SIZE;
        else
            ei->EndOfFile.QuadPart = 0;
    } else if (FileInformationClass == WW_FileAllocationInformation && Length >= sizeof(LARGE_INTEGER)) {
        LARGE_INTEGER *al = (LARGE_INTEGER *)FileInformation;
        if (al->QuadPart >= WWFLT_HEADER_SIZE)
            al->QuadPart -= WWFLT_HEADER_SIZE;
        else
            al->QuadPart = 0;
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
     * NtClose, NtSetInformationFile, NtQueryInformationFile,
     * NtCreateSection, NtDuplicateObject, NtCopyFileChunk,
     * NtWriteFileGather. */
    static char gAttachStatus[12] = "???????????";

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
        if (!gOrigNtCreateSection) gOrigNtCreateSection = (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection");
        if (!gOrigNtMapViewOfSection) gOrigNtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");
        if (!gOrigNtUnmapViewOfSection) gOrigNtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
        if (!gOrigNtDuplicateObject) gOrigNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(ntdll, "NtDuplicateObject");
        if (!gOrigNtCopyFileChunk) gOrigNtCopyFileChunk = (NtCopyFileChunk_t)GetProcAddress(ntdll, "NtCopyFileChunk");
        if (!gOrigNtWriteFileGather) gOrigNtWriteFileGather = (NtWriteFileGather_t)GetProcAddress(ntdll, "NtWriteFileGather");
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
    WW_ATTACH(&gOrigNtCreateSection, WwHookNtCreateSection, "NtCreateSection", gAttachStatus, 7);
    WW_ATTACH(&gOrigNtDuplicateObject, WwHookNtDuplicateObject, "NtDuplicateObject", gAttachStatus, 8);
    WW_ATTACH(&gOrigNtCopyFileChunk, WwHookNtCopyFileChunk, "NtCopyFileChunk", gAttachStatus, 9);
    WW_ATTACH(&gOrigNtWriteFileGather, WwHookNtWriteFileGather, "NtWriteFileGather", gAttachStatus, 10);
    err = DetourTransactionCommit();
    if (err != NO_ERROR) {
        DetourTransactionAbort();
        return 0;
    }
    {
        int i;
        for (i = 0; i < 11; i++) if (gAttachStatus[i] == '1') n++;
    }
    /* Keep the status string visible to DllMain's attach log. */
    {
        extern char gWwAttachStatus[12];
        memcpy(gWwAttachStatus, gAttachStatus, 12);
    }
    return n;
}
char gWwAttachStatus[12] = "???????????";

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
            extern char gWwAttachStatus[12];
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
