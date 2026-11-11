/* wwflt.c -- WWFilter minifilter driver: clean-room transparent file
 * encryption. No vendor binary is used; only the documented policy and
 * encryption logic are followed (see DESIGN.md).
 *
 * Layout:
 *   1. Globals, policy table, event ring, status counters
 *   2. Helpers: wildcard match, extension match, process exe lookup
 *   3. Stream context + policy evaluation + header read/write
 *   4. Operation callbacks (create/read/write/set_info/query_info/cleanup)
 *   5. Control device + IOCTL dispatch (policy/status/events/log/config)
 *   6. DriverEntry / DriverUnload / instance setup
 *
 * Hard rules (see DESIGN.md):
 * - Only encrypt/decrypt at paging I/O (IRP_PAGING_IO) or non-cached
 *   I/O (IRP_NOCACHE). Never touch cached I/O. The cache holds plaintext.
 * - The 512-byte header is never encrypted. Data always starts at
 *   physical offset 512. The counter for a byte is its logical offset.
 * - If the encryption state is inconsistent, fail the I/O instead of
 *   proceeding with possibly-wrong data.
 * - Free every stream context via the cleanup callback; free every
 *   lookaside buffer exactly once.
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "wwflt.h"
#include "sbox.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode")

/* ------------------------------------------------------------------ */
/* 1. Globals, policy table, event ring, status                        */
/* ------------------------------------------------------------------ */

#define WWFLT_TAG            'tlFW'
#define WWFLT_EVENT_RING_SIZE 4096
#define WWFLT_MAX_VOLUMES    64

static PFLT_FILTER gFilter = NULL;
static PDEVICE_OBJECT gControlDevice = NULL;

/* Active policy table. Swapped atomically on SET_POLICY (copy-on-write:
 * build the new table, then exchange the pointer under the lock; readers
 * take the lock in shared mode or use the pointer with an ERESOURCE).
 * A NULL table means "no policy installed yet" (pass everything through). */
static PWWFLT_POLICY gPolicy = NULL;
static ERESOURCE gPolicyLock;

/* Driver enabled flag (SET_CONFIG). When 0, every callback passes through. */
static volatile LONG gEnabled = 1;

/* Log level (SET_LOG_LEVEL): 0=errors only, 1=crypto events, 2=policy. */
static volatile LONG gLogLevel = 1;

/* Event ring: fixed size, overwrites the oldest when full. */
static WWFLT_EVENT gEventRing[WWFLT_EVENT_RING_SIZE];
static volatile LONG gEventWrite = 0;   /* next slot to write (monotonic) */
static volatile LONG gEventRead = 0;    /* next slot to read (monotonic) */
static volatile LONG gEventDropped = 0; /* events overwritten before being read */
static KSPIN_LOCK gEventLock;

/* Status counters (updated with Interlocked*). */
static volatile LONG gEncryptedFilesOpen = 0;
static volatile ULONGLONG gBytesEncrypted = 0;
static volatile ULONGLONG gBytesDecrypted = 0;
static volatile ULONGLONG gPolicyLookups = 0;
static volatile ULONGLONG gIoFiltered = 0;
static volatile ULONGLONG gErrors = 0;

/* Lookaside list for swap buffers (used when we must not encrypt in place). */
static NPAGED_LOOKASIDE_LIST gSwapLookaside;

/* The header magic (16 bytes). */
static const UCHAR gMagic[WWFLT_MAGIC_SIZE] = WWFLT_MAGIC_BYTES;

/* ------------------------------------------------------------------ */
/* Event ring                                                          */
/* ------------------------------------------------------------------ */

static void WwLogEvent(ULONG type, ULONG pid, PCWSTR process, PCWSTR path,
                       ULONGLONG offset, ULONG length, NTSTATUS status)
{
    LONG idx;
    WWFLT_EVENT *ev;
    LARGE_INTEGER now;
    KIRQL oldIrql;

    if (type == WWFLT_EVENT_ERROR) {
        if (gLogLevel < 0) return;
    } else if (type == WWFLT_EVENT_POLICY) {
        if (gLogLevel < 2) return;
    } else {
        if (gLogLevel < 1) return;
    }
    KeQuerySystemTime(&now);
    KeAcquireSpinLock(&gEventLock, &oldIrql);
    idx = (LONG)(gEventWrite % WWFLT_EVENT_RING_SIZE);
    ev = &gEventRing[idx];
    ev->timestamp_100ns = (ULONGLONG)now.QuadPart;
    ev->type = type;
    ev->pid = pid;
    ev->status = (LONG)status;
    ev->offset = offset;
    ev->length = length;
    if (process) {
        wcsncpy(ev->process, process, WWFLT_MAX_EXE_LEN - 1);
        ev->process[WWFLT_MAX_EXE_LEN - 1] = L'\0';
    } else {
        ev->process[0] = L'\0';
    }
    if (path) {
        wcsncpy(ev->path, path, WWFLT_MAX_EVENT_PATH - 1);
        ev->path[WWFLT_MAX_EVENT_PATH - 1] = L'\0';
    } else {
        ev->path[0] = L'\0';
    }
    gEventWrite++;
    if ((gEventWrite - gEventRead) > WWFLT_EVENT_RING_SIZE) {
        /* Ring wrapped: the oldest unread event is gone. */
        gEventRead = gEventWrite - WWFLT_EVENT_RING_SIZE;
        gEventDropped++;
    }
    KeReleaseSpinLock(&gEventLock, oldIrql);
}

/* ------------------------------------------------------------------ */
/* 2. Helpers: wildcard match, extension match, process exe lookup     */
/* ------------------------------------------------------------------ */

/* Case-insensitive wildcard match ('*' and '?'), for path rules.
 * Returns TRUE if `str` matches `pattern`. */
static BOOLEAN WwWildcardMatch(PCWSTR pattern, PCWSTR str)
{
    /* Iterative wildcard match with backtracking on '*'. */
    PCWSTR p = pattern, s = str;
    PCWSTR star_p = NULL, star_s = NULL;
    while (*s) {
        if (*p == L'*') {
            star_p = p++;
            star_s = s;
        } else if (*p == L'?' || towlower(*p) == towlower(*s)) {
            p++;
            s++;
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

/* Case-insensitive ASCII/Unicode lowercasing for a single WCHAR.
 * Only A-Z are folded; other characters compare as-is (exe names and
 * extensions are ASCII in practice). */
static WCHAR WwToLower(WCHAR c)
{
    if (c >= L'A' && c <= L'Z') return (WCHAR)(c + (L'a' - L'A'));
    return c;
}

/* Case-insensitive wide-string compare. Returns 0 when equal. */
static int WwWcsIcmp(PCWSTR a, PCWSTR b)
{
    while (*a && *b) {
        WCHAR ca = WwToLower(*a), cb = WwToLower(*b);
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)WwToLower(*a) - (int)WwToLower(*b);
}

/* Check whether `ext` (without the dot, e.g. L"txt") is in the '|'
 * separated `ext_list` (e.g. L"txt|pdf"). Case-insensitive. */
static BOOLEAN WwExtInList(PCWSTR ext_list, PCWSTR ext)
{
    PCWSTR p = ext_list;
    if (!ext || !*ext) return FALSE;
    while (*p) {
        PCWSTR start = p;
        size_t n = 0;
        while (*p && *p != L'|') { p++; n++; }
        if (n > 0 && n == wcslen(ext)) {
            size_t i;
            BOOLEAN same = TRUE;
            for (i = 0; i < n; i++) {
                if (WwToLower(start[i]) != WwToLower(ext[i])) { same = FALSE; break; }
            }
            if (same) return TRUE;
        }
        if (*p == L'|') p++;
    }
    return FALSE;
}

/* Get the requesting process's image file name (e.g. L"notepad.exe").
 * `out` receives a NUL-terminated lowercase name. Returns STATUS_SUCCESS
 * or an error. The caller must be at PASSIVE_LEVEL. */
static NTSTATUS WwGetRequestorExe(PFLT_CALLBACK_DATA Data, PWSTR out, size_t out_chars)
{
    PEPROCESS proc;
    NTSTATUS st;
    PUNICODE_STRING image = NULL;
    PWSTR slash;
    size_t len;

    proc = FltGetRequestorProcess(Data);
    if (!proc) return STATUS_UNSUCCESSFUL;
    st = SeLocateProcessImageName(proc, &image);
    if (!NT_SUCCESS(st)) return st;
    if (!image || !image->Buffer) {
        if (image) ExFreePool(image);
        return STATUS_UNSUCCESSFUL;
    }
    slash = wcsrchr(image->Buffer, L'\\');
    {
        PCWSTR base = slash ? slash + 1 : image->Buffer;
        len = wcslen(base);
        if (len >= out_chars) len = out_chars - 1;
        wcsncpy(out, base, len);
        out[len] = L'\0';
    }
    ExFreePool(image);
    return STATUS_SUCCESS;
}

/* Extract the extension (without the dot) from a file name.
 * Returns a pointer into a caller-provided buffer, or NULL if none. */
static PCWSTR WwGetExtension(PCWSTR file_name, PWSTR ext_buf, size_t ext_chars)
{
    PCWSTR dot = wcsrchr(file_name, L'.');
    PCWSTR slash = wcsrchr(file_name, L'\\');
    if (!dot || (slash && dot < slash)) return NULL;
    dot++;
    if (!*dot) return NULL;
    wcsncpy(ext_buf, dot, ext_chars - 1);
    ext_buf[ext_chars - 1] = L'\0';
    return ext_buf;
}

/* ------------------------------------------------------------------ */
/* 3. Stream context + policy evaluation + header                      */
/* ------------------------------------------------------------------ */

/* Per-file-stream encryption state. Allocated at create time when the
 * policy says the file should be encrypted; freed by the Filter Manager
 * via WwStreamContextCleanup when the stream is torn down. */
typedef struct _WWFLT_STREAM_CTX {
    BOOLEAN is_encrypted;                  /* file has (or will get) a header */
    ULONG mode;                            /* WWFLT_ENCRYPT_READ/WRITE */
    BOOLEAN header_written;                /* header already on disk */
    BOOLEAN header_checked;                /* header work claimed by one post-create */
    KEVENT header_ready;                   /* set when header work completes; later opens wait on it */
    UCHAR key[WWFLT_KEY_SIZE];
    WW_SBOX_CTX sbox;
    WCHAR policy_name[WWFLT_MAX_GROUP_LEN]; /* e.g. L"NOTEPAD." */
    ERESOURCE lock;                        /* guards header_written / sbox */
} WWFLT_STREAM_CTX;

/* Forward declaration (used by gContextRegs below). */
static VOID WwStreamContextCleanup(PFLT_CONTEXT ctx, FLT_CONTEXT_TYPE type);

static const FLT_CONTEXT_REGISTRATION gContextRegs[] = {
    { FLT_STREAM_CONTEXT, 0, WwStreamContextCleanup, sizeof(WWFLT_STREAM_CTX), 'xtSW' },
    { FLT_CONTEXT_END }
};

/* Context cleanup: free the ERESOURCE and let the Filter Manager free
 * the context memory itself. Called when the stream is torn down. */
static VOID WwStreamContextCleanup(PFLT_CONTEXT ctx, FLT_CONTEXT_TYPE type)
{
    WWFLT_STREAM_CTX *sctx = (WWFLT_STREAM_CTX *)ctx;
    UNREFERENCED_PARAMETER(type);
    if (sctx->is_encrypted) {
        InterlockedDecrement(&gEncryptedFilesOpen);
    }
    ExDeleteResourceLite(&sctx->lock);
}

/* Find the process rule for `exe` in the active policy table.
 * Returns a pointer to the rule inside the table (valid only while the
 * caller holds gPolicyLock in shared mode), or NULL. The caller must
 * hold the lock. */
static const WWFLT_PROC_RULE *WwFindProcRuleLocked(PCWSTR exe)
{
    ULONG i;
    if (!gPolicy) return NULL;
    for (i = 0; i < gPolicy->proc_count; i++) {
        if (WwWcsIcmp(gPolicy->procs[i].exe, exe) == 0) {
            return &gPolicy->procs[i];
        }
    }
    return NULL;
}

/* Evaluate the policy for a file being opened.
 * Inputs: requesting exe name, full file path, file name (for extension).
 * Outputs (via out_*): whether the file should be encrypted, the mode,
 * and a copy of the matching process rule's extension list is NOT needed
 * (the caller only needs the decision). Returns TRUE if the file should
 * be encrypted (or read-decrypted), FALSE if it passes through.
 * Must be called at PASSIVE_LEVEL with no locks held. */
static BOOLEAN WwEvaluatePolicy(PCWSTR exe, PCWSTR full_path, PCWSTR file_name,
                                ULONG *out_mode, WCHAR *out_policy_name, size_t policy_chars)
{
    const WWFLT_PROC_RULE *rule;
    WCHAR ext[WWFLT_MAX_EXT_LEN];
    PCWSTR extp;
    ULONG i;
    BOOLEAN path_ok = FALSE;

    InterlockedIncrement64((volatile LONGLONG *)&gPolicyLookups);
    ExAcquireResourceSharedLite(&gPolicyLock, TRUE);
    rule = WwFindProcRuleLocked(exe);
    if (!rule || rule->encrypt_mode == WWFLT_ENCRYPT_NONE) {
        ExReleaseResourceLite(&gPolicyLock);
        return FALSE;
    }
    /* Extension must be in this process's File list. */
    extp = WwGetExtension(file_name, ext, WWFLT_MAX_EXT_LEN);
    if (!extp || !WwExtInList(rule->ext_list, extp)) {
        ExReleaseResourceLite(&gPolicyLock);
        return FALSE;
    }
    /* Path must match at least one dir/wild/include rule (if any). */
    if (rule->path_rule_count == 0) {
        path_ok = TRUE;
    } else {
        for (i = 0; i < rule->path_rule_count; i++) {
            if (WwWildcardMatch(rule->path_rules[i], full_path)) { path_ok = TRUE; break; }
        }
    }
    if (!path_ok) {
        ExReleaseResourceLite(&gPolicyLock);
        return FALSE;
    }
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
    ExReleaseResourceLite(&gPolicyLock);
    return TRUE;
}

/* Read the 512-byte header of an already-open file (via the file object)
 * into `hdr`. Returns STATUS_SUCCESS if the header was read, or an error.
 * Must be called at PASSIVE_LEVEL. The caller must hold no locks. */
static NTSTATUS WwReadHeader(PFLT_INSTANCE inst, PFILE_OBJECT file_obj, UCHAR hdr[WWFLT_HEADER_SIZE])
{
    NTSTATUS st;
    ULONG bytes_read = 0;
    LARGE_INTEGER off;
    off.QuadPart = 0;
    st = FltReadFile(inst, file_obj, &off, WWFLT_HEADER_SIZE, hdr, FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &bytes_read, NULL, NULL);
    if (!NT_SUCCESS(st)) return st;
    if (bytes_read < WWFLT_HEADER_SIZE) return STATUS_END_OF_FILE;
    return STATUS_SUCCESS;
}

/* Write the 512-byte header to an already-open file at offset 0.
 * Must be called at PASSIVE_LEVEL. */
static NTSTATUS WwWriteHeader(PFLT_INSTANCE inst, PFILE_OBJECT file_obj, const UCHAR hdr[WWFLT_HEADER_SIZE])
{
    NTSTATUS st;
    ULONG bytes_written = 0;
    LARGE_INTEGER off;
    off.QuadPart = 0;
    st = FltWriteFile(inst, file_obj, &off, WWFLT_HEADER_SIZE, (PUCHAR)hdr, FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &bytes_written, NULL, NULL);
    if (!NT_SUCCESS(st)) return st;
    if (bytes_written < WWFLT_HEADER_SIZE) return STATUS_UNSUCCESSFUL;
    return STATUS_SUCCESS;
}

/* Build a 512-byte header for a new encrypted file. `policy_name` is the
 * ASCII policy name (e.g. "NOTEPAD."). `key` is 32 random bytes.
 * The header bytes +0x12..0x1ff are encrypted with counter starting at 0
 * (matching the old client's format). The caller provides a zeroed 512-byte
 * buffer; this fills it. */
static void WwBuildHeader(UCHAR hdr[WWFLT_HEADER_SIZE], const char *policy_name, const UCHAR key[WWFLT_KEY_SIZE])
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
    /* Encrypt header bytes +0x12..0x1ff with counter starting at 0.
     * The key is used as-is (the header's own key) to build the S-box,
     * matching the old client: the header is encrypted with the file's key. */
    WwSboxInit(&tmp, WWFLT_CURRENT_VERSION, key);
    WwSboxEncrypt(&tmp, hdr + WWFLT_HEADER_POLICY_OFF, WWFLT_HEADER_SIZE - WWFLT_HEADER_POLICY_OFF, 0);
}

/* Parse a header that was read from disk. The header bytes +0x12..0x1ff
 * arrive encrypted; decrypt them with the key stored at +0x30 (the key
 * itself is stored as-is, not encrypted). On success, fills `key` and
 * `version` and returns TRUE if the magic matches. */
static BOOLEAN WwParseHeader(UCHAR hdr[WWFLT_HEADER_SIZE], UCHAR key[WWFLT_KEY_SIZE], int *version)
{
    WW_SBOX_CTX tmp;
    if (memcmp(hdr, gMagic, WWFLT_MAGIC_SIZE) != 0) return FALSE;
    *version = hdr[WWFLT_HEADER_VERSION_OFF] | (hdr[WWFLT_HEADER_VERSION_OFF + 1] << 8);
    if (*version != WWFLT_VERSION_1 && *version != WWFLT_VERSION_2) return FALSE;
    memcpy(key, hdr + WWFLT_HEADER_KEY_OFF, WWFLT_KEY_SIZE);
    /* Decrypt header bytes +0x12..0x1ff with counter starting at 0. */
    WwSboxInit(&tmp, *version, key);
    WwSboxDecrypt(&tmp, hdr + WWFLT_HEADER_POLICY_OFF, WWFLT_HEADER_SIZE - WWFLT_HEADER_POLICY_OFF, 0);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* 4. Operation callbacks                                              */
/* ------------------------------------------------------------------ */

/* IRP_MJ_CREATE pre-op: evaluate the policy. If the file should be
 * encrypted, attach a stream context and ask for the post-op callback. */
static FLT_PREOP_CALLBACK_STATUS WwPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    NTSTATUS st;
    PFLT_FILE_NAME_INFORMATION name_info = NULL;
    WCHAR exe[WWFLT_MAX_EXE_LEN];
    ULONG mode = WWFLT_ENCRYPT_NONE;
    WCHAR policy_name[WWFLT_MAX_GROUP_LEN];
    WWFLT_STREAM_CTX *sctx = NULL;
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!gEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FltObjects->FileObject && FltObjects->FileObject->FsContext == NULL) {
        /* Opening by file ID / no stream yet; let it through. */
    }
    st = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name_info);
    if (!NT_SUCCESS(st)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    st = FltParseFileNameInformation(name_info);
    if (!NT_SUCCESS(st)) { FltReleaseFileNameInformation(name_info); return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    if (WwGetRequestorExe(Data, exe, WWFLT_MAX_EXE_LEN) != STATUS_SUCCESS) {
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* Directories are never encrypted. */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!WwEvaluatePolicy(exe, name_info->Name.Buffer, name_info->FinalComponent.Buffer, &mode, policy_name, WWFLT_MAX_GROUP_LEN)) {
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* Policy says encrypt (or read-decrypt). Attach a stream context. */
    st = FltAllocateContext(gFilter, FLT_STREAM_CONTEXT, sizeof(WWFLT_STREAM_CTX), NonPagedPool, (PFLT_CONTEXT *)&sctx);
    if (!NT_SUCCESS(st)) {
        FltReleaseFileNameInformation(name_info);
        InterlockedIncrement64((volatile LONGLONG *)&gErrors);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    memset(sctx, 0, sizeof(*sctx));
    sctx->mode = mode;
    sctx->is_encrypted = FALSE;   /* decided in post-create (header check) */
    sctx->header_written = FALSE;
    sctx->header_checked = FALSE;
    KeInitializeEvent(&sctx->header_ready, NotificationEvent, FALSE);
    wcsncpy(sctx->policy_name, policy_name, WWFLT_MAX_GROUP_LEN - 1);
    ExInitializeResourceLite(&sctx->lock);
    st = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, sctx, NULL);
    if (!NT_SUCCESS(st) && st != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        ExDeleteResourceLite(&sctx->lock);
        FltReleaseContext(sctx);
        FltReleaseFileNameInformation(name_info);
        InterlockedIncrement64((volatile LONGLONG *)&gErrors);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltReleaseContext(sctx);
    FltReleaseFileNameInformation(name_info);
    if (gLogLevel >= 2) {
        WwLogEvent(WWFLT_EVENT_POLICY, HandleToUlong(PsGetCurrentProcessId()), exe, NULL, 0, 0, STATUS_SUCCESS);
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* IRP_MJ_CREATE post-op: the file is now open. Decide whether it is
 * already encrypted (read the header) or needs a header (new file). */
static FLT_POSTOP_CALLBACK_STATUS WwPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POSTOP_FLAGS Flags)
{
    NTSTATUS st;
    WWFLT_STREAM_CTX *sctx = NULL;
    UCHAR hdr[WWFLT_HEADER_SIZE];
    UCHAR key[WWFLT_KEY_SIZE];
    int version = WWFLT_CURRENT_VERSION;
    BOOLEAN is_new = FALSE;
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;
    st = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&sctx);
    if (!NT_SUCCESS(st)) return FLT_POSTOP_FINISHED_PROCESSING;
    /* Claim the header work once (so only one thread does the header I/O),
     * then do the I/O WITHOUT holding the lock: the header write itself
     * goes through our own write callback, which must not block on this
     * lock (it would deadlock). Later opens wait on header_ready so they
     * never do I/O before the header decision is final. */
    ExAcquireResourceExclusiveLite(&sctx->lock, TRUE);
    if (sctx->header_checked) {
        ExReleaseResourceLite(&sctx->lock);
        /* Another post-create is doing (or did) the header work. Wait for
         * it (post-create runs at PASSIVE_LEVEL, so waiting is fine). */
        {
            LARGE_INTEGER timeout;
            NTSTATUS wst;
            timeout.QuadPart = -50000000LL; /* 5 seconds */
            wst = KeWaitForSingleObject(&sctx->header_ready, Executive, KernelMode, FALSE, &timeout);
            if (!NT_SUCCESS(wst)) {
                InterlockedIncrement64((volatile LONGLONG *)&gErrors);
            }
        }
        FltReleaseContext(sctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    sctx->header_checked = TRUE;
    ExReleaseResourceLite(&sctx->lock);
    /* Was the file just created (empty)? */
    is_new = (Data->IoStatus.Information == FILE_CREATED);
    if (is_new) {
        /* New file: if mode is Write, write the header now. */
        if (sctx->mode == WWFLT_ENCRYPT_WRITE) {
            char policy_ascii[WWFLT_MAX_GROUP_LEN];
            size_t i;
            BOOLEAN header_ok = FALSE;
            for (i = 0; i < WWFLT_MAX_GROUP_LEN - 1 && sctx->policy_name[i]; i++) {
                policy_ascii[i] = (char)sctx->policy_name[i];
            }
            policy_ascii[i] = '\0';
            /* Random per-file key. RtlGenRandom is the kernel RNG. */
            if (!RtlGenRandom(key, WWFLT_KEY_SIZE)) {
                /* Fallback: derive from time + counter (never ideal, but
                 * better than failing the create). */
                LARGE_INTEGER t;
                KeQuerySystemTime(&t);
                for (i = 0; i < WWFLT_KEY_SIZE; i++) {
                    key[i] = (UCHAR)((t.QuadPart >> (i % 8)) & 0xff);
                }
            }
            WwBuildHeader(hdr, policy_ascii, key);
            st = WwWriteHeader(FltObjects->Instance, FltObjects->FileObject, hdr);
            if (NT_SUCCESS(st)) {
                header_ok = TRUE;
            } else {
                InterlockedIncrement64((volatile LONGLONG *)&gErrors);
            }
            if (header_ok) {
                ExAcquireResourceExclusiveLite(&sctx->lock, TRUE);
                memcpy(sctx->key, key, WWFLT_KEY_SIZE);
                WwSboxInit(&sctx->sbox, WWFLT_CURRENT_VERSION, key);
                sctx->is_encrypted = TRUE;
                sctx->header_written = TRUE;
                ExReleaseResourceLite(&sctx->lock);
                InterlockedIncrement(&gEncryptedFilesOpen);
            }
        }
        /* Read mode on a new file: nothing to decrypt; leave unencrypted. */
    } else {
        /* Existing file: read the header to see if it is encrypted. */
        st = WwReadHeader(FltObjects->Instance, FltObjects->FileObject, hdr);
        if (NT_SUCCESS(st) && WwParseHeader(hdr, key, &version)) {
            ExAcquireResourceExclusiveLite(&sctx->lock, TRUE);
            memcpy(sctx->key, key, WWFLT_KEY_SIZE);
            WwSboxInit(&sctx->sbox, version, key);
            sctx->is_encrypted = TRUE;
            sctx->header_written = TRUE;
            ExReleaseResourceLite(&sctx->lock);
            InterlockedIncrement(&gEncryptedFilesOpen);
        } else {
            /* Plaintext file (no header). Leave is_encrypted FALSE.
             * Phase 1 does NOT convert an existing plaintext file to
             * encrypted on first write; only newly created files get a
             * header. (See DESIGN.md section 8.) */
        }
    }
    /* Header work is done; wake any later opens waiting on it. */
    KeSetEvent(&sctx->header_ready, IO_NO_INCREMENT, FALSE);
    FltReleaseContext(sctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* Helper: get the stream context for an I/O operation. Returns NULL if
 * the file is not tracked (not encrypted). The caller must release it. */
static WWFLT_STREAM_CTX *WwGetCtx(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
    WWFLT_STREAM_CTX *sctx = NULL;
    NTSTATUS st;
    UNREFERENCED_PARAMETER(Data);
    st = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&sctx);
    if (!NT_SUCCESS(st)) return NULL;
    if (!sctx->is_encrypted) { FltReleaseContext(sctx); return NULL; }
    return sctx;
}

/* IRP_MJ_READ pre-op: only paging/non-cached reads need offset fixup.
 * Cached reads come from the cache (plaintext) and pass through untouched. */
static FLT_PREOP_CALLBACK_STATUS WwPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    WWFLT_STREAM_CTX *sctx;
    UNREFERENCED_PARAMETER(CompletionContext);
    if (!gEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!(Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_NOCACHE))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;   /* cached read: cache holds plaintext */
    }
    sctx = WwGetCtx(Data, FltObjects);
    if (!sctx) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    InterlockedIncrement64((volatile LONGLONG *)&gIoFiltered);
    /* Shift the read to the physical offset (logical + 512). The post-op
     * will decrypt the buffer using the logical offset as the counter. */
    Data->Iopb->Parameters.Read.ByteOffset.QuadPart += WWFLT_HEADER_SIZE;
    FltReleaseContext(sctx);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* IRP_MJ_READ post-op: decrypt the buffer read from disk. Only called
 * for paging/non-cached reads (see WwPreRead). */
static FLT_POSTOP_CALLBACK_STATUS WwPostRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POSTOP_FLAGS Flags)
{
    WWFLT_STREAM_CTX *sctx;
    PVOID buf = NULL;
    ULONG len = 0;
    LONGLONG logical_off;
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->IoStatus.Information == 0) return FLT_POSTOP_FINISHED_PROCESSING;
    sctx = WwGetCtx(Data, FltObjects);
    if (!sctx) return FLT_POSTOP_FINISHED_PROCESSING;
    /* The buffer is in the MDL (paging I/O) or the user buffer. Use the
     * MDL when present (paging I/O always has one). */
    if (Data->Iopb->Parameters.Read.MdlAddress) {
        buf = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority);
    } else if (Data->Iopb->Parameters.Read.ReadBuffer) {
        buf = Data->Iopb->Parameters.Read.ReadBuffer;
    }
    len = (ULONG)Data->IoStatus.Information;
    if (!buf || len == 0) { FltReleaseContext(sctx); return FLT_POSTOP_FINISHED_PROCESSING; }
    /* Logical offset = physical offset - 512 (we added 512 in pre-op). */
    logical_off = Data->Iopb->Parameters.Read.ByteOffset.QuadPart - WWFLT_HEADER_SIZE;
    if (logical_off < 0) {
        /* Should not happen; fail closed rather than decrypt wrong bytes. */
        Data->IoStatus.Status = STATUS_DATA_ERROR;
        Data->IoStatus.Information = 0;
        InterlockedIncrement64((volatile LONGLONG *)&gErrors);
        FltReleaseContext(sctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    ExAcquireResourceSharedLite(&sctx->lock, TRUE);
    WwSboxDecrypt(&sctx->sbox, (UCHAR *)buf, len, (unsigned long long)logical_off);
    ExReleaseResourceLite(&sctx->lock);
    InterlockedAdd64((volatile LONGLONG *)&gBytesDecrypted, len);
    FltReleaseContext(sctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* Swap-buffer completion context for writes. A paging write references
 * a cache page (via the MDL); encrypting that page in place would corrupt
 * the cache (it would then hold ciphertext). So we copy the plaintext
 * into a separate swap buffer, encrypt the copy, and swap the MDL/buffer
 * so the file system writes the encrypted copy to disk. The post-op
 * restores the original MDL/buffer and frees the swap buffer. */
typedef struct _WWFLT_WRITE_CTX {
    PMDL orig_mdl;          /* original MDL (NULL if the write used a user buffer) */
    PVOID orig_buffer;      /* original user buffer (NULL if MDL-based) */
    PMDL swap_mdl;          /* MDL we built for the swap buffer (NULL if user buffer) */
    PVOID swap_buffer;      /* encrypted copy */
    ULONG length;
} WWFLT_WRITE_CTX;

/* IRP_MJ_WRITE pre-op: only paging/non-cached writes are encrypted here.
 * Cached writes go into the cache as plaintext; they are encrypted when
 * the cache flushes (as a paging write). Uses a swap buffer (never
 * encrypts the cached page or the app's buffer in place). */
static FLT_PREOP_CALLBACK_STATUS WwPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    WWFLT_STREAM_CTX *sctx;
    WWFLT_WRITE_CTX *wctx = NULL;
    PVOID src_buf = NULL;
    ULONG len = 0;
    LONGLONG logical_off;
    if (!gEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!(Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_NOCACHE))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;   /* cached write: cache holds plaintext */
    }
    sctx = WwGetCtx(Data, FltObjects);
    if (!sctx) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* Read mode never encrypts on write. */
    if (sctx->mode != WWFLT_ENCRYPT_WRITE) { FltReleaseContext(sctx); return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    InterlockedIncrement64((volatile LONGLONG *)&gIoFiltered);
    len = Data->Iopb->Parameters.Write.Length;
    if (len == 0) { FltReleaseContext(sctx); return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    if (Data->Iopb->Parameters.Write.MdlAddress) {
        src_buf = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);
    } else if (Data->Iopb->Parameters.Write.WriteBuffer) {
        src_buf = Data->Iopb->Parameters.Write.WriteBuffer;
    }
    if (!src_buf) { FltReleaseContext(sctx); return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    logical_off = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
    if (logical_off < 0) {
        Data->IoStatus.Status = STATUS_DATA_ERROR;
        Data->IoStatus.Information = 0;
        InterlockedIncrement64((volatile LONGLONG *)&gErrors);
        FltReleaseContext(sctx);
        return FLT_PREOP_COMPLETE;
    }
    /* Allocate the swap buffer + completion context. */
    wctx = (WWFLT_WRITE_CTX *)ExAllocatePoolWithTag(NonPagedPool, sizeof(WWFLT_WRITE_CTX), WWFLT_TAG);
    if (!wctx) {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        InterlockedIncrement64((volatile LONGLONG *)&gErrors);
        FltReleaseContext(sctx);
        return FLT_PREOP_COMPLETE;
    }
    memset(wctx, 0, sizeof(*wctx));
    wctx->length = len;
    wctx->swap_buffer = ExAllocatePoolWithTag(NonPagedPool, len, WWFLT_TAG);
    if (!wctx->swap_buffer) {
        ExFreePoolWithTag(wctx, WWFLT_TAG);
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        InterlockedIncrement64((volatile LONGLONG *)&gErrors);
        FltReleaseContext(sctx);
        return FLT_PREOP_COMPLETE;
    }
    memcpy(wctx->swap_buffer, src_buf, len);
    ExAcquireResourceSharedLite(&sctx->lock, TRUE);
    WwSboxEncrypt(&sctx->sbox, (UCHAR *)wctx->swap_buffer, len, (unsigned long long)logical_off);
    ExReleaseResourceLite(&sctx->lock);
    /* Swap the buffer in. For MDL-based I/O, build an MDL for the swap
     * buffer and replace the IRP's MDL; for a user buffer, swap the pointer. */
    if (Data->Iopb->Parameters.Write.MdlAddress) {
        wctx->orig_mdl = Data->Iopb->Parameters.Write.MdlAddress;
        wctx->swap_mdl = IoAllocateMdl(wctx->swap_buffer, len, FALSE, FALSE, NULL);
        if (!wctx->swap_mdl) {
            ExFreePoolWithTag(wctx->swap_buffer, WWFLT_TAG);
            ExFreePoolWithTag(wctx, WWFLT_TAG);
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            InterlockedIncrement64((volatile LONGLONG *)&gErrors);
            FltReleaseContext(sctx);
            return FLT_PREOP_COMPLETE;
        }
        MmBuildMdlForNonPagedPool(wctx->swap_mdl);
        Data->Iopb->Parameters.Write.MdlAddress = wctx->swap_mdl;
        Data->Iopb->Irp->MdlAddress = wctx->swap_mdl;
    } else {
        wctx->orig_buffer = Data->Iopb->Parameters.Write.WriteBuffer;
        Data->Iopb->Parameters.Write.WriteBuffer = wctx->swap_buffer;
    }
    Data->Iopb->Parameters.Write.ByteOffset.QuadPart += WWFLT_HEADER_SIZE;
    InterlockedAdd64((volatile LONGLONG *)&gBytesEncrypted, len);
    *CompletionContext = wctx;
    FltReleaseContext(sctx);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* IRP_MJ_WRITE post-op: restore the original MDL/buffer and free the
 * swap buffer. Runs for every write that WwPreWrite swapped. */
static FLT_POSTOP_CALLBACK_STATUS WwPostWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POSTOP_FLAGS Flags)
{
    WWFLT_WRITE_CTX *wctx = (WWFLT_WRITE_CTX *)CompletionContext;
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    if (!wctx) return FLT_POSTOP_FINISHED_PROCESSING;
    if (wctx->swap_mdl) {
        Data->Iopb->Parameters.Write.MdlAddress = wctx->orig_mdl;
        Data->Iopb->Irp->MdlAddress = wctx->orig_mdl;
        IoFreeMdl(wctx->swap_mdl);
    } else if (wctx->orig_buffer) {
        Data->Iopb->Parameters.Write.WriteBuffer = wctx->orig_buffer;
    }
    if (wctx->swap_buffer) ExFreePoolWithTag(wctx->swap_buffer, WWFLT_TAG);
    ExFreePoolWithTag(wctx, WWFLT_TAG);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* IRP_MJ_SET_INFORMATION pre-op: adjust end-of-file / allocation sizes
 * by +512 so the on-disk file holds the header. */
static FLT_PREOP_CALLBACK_STATUS WwPreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    WWFLT_STREAM_CTX *sctx;
    FILE_INFORMATION_CLASS fic;
    UNREFERENCED_PARAMETER(CompletionContext);
    if (!gEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    fic = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (fic != FileEndOfFileInformation && fic != FileAllocationInformation) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    sctx = WwGetCtx(Data, FltObjects);
    if (!sctx) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (fic == FileEndOfFileInformation) {
        PFILE_END_OF_FILE_INFORMATION info = (PFILE_END_OF_FILE_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        info->EndOfFile.QuadPart += WWFLT_HEADER_SIZE;
    } else {
        PFILE_ALLOCATION_INFORMATION info = (PFILE_ALLOCATION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        info->AllocationSize.QuadPart += WWFLT_HEADER_SIZE;
    }
    FltReleaseContext(sctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* IRP_MJ_QUERY_INFORMATION post-op: report the logical size (physical - 512). */
static FLT_POSTOP_CALLBACK_STATUS WwPostQueryInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POSTOP_FLAGS Flags)
{
    WWFLT_STREAM_CTX *sctx;
    FILE_INFORMATION_CLASS fic;
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;
    fic = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
    if (fic != FileStandardInformation && fic != FileAllInformation && fic != FileNetworkOpenInformation) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    sctx = WwGetCtx(Data, FltObjects);
    if (!sctx) return FLT_POSTOP_FINISHED_PROCESSING;
    if (fic == FileStandardInformation) {
        PFILE_STANDARD_INFORMATION info = (PFILE_STANDARD_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
        if (info->EndOfFile.QuadPart >= WWFLT_HEADER_SIZE) info->EndOfFile.QuadPart -= WWFLT_HEADER_SIZE;
        else info->EndOfFile.QuadPart = 0;
        if (info->AllocationSize.QuadPart >= WWFLT_HEADER_SIZE) info->AllocationSize.QuadPart -= WWFLT_HEADER_SIZE;
        else info->AllocationSize.QuadPart = 0;
    } else if (fic == FileAllInformation) {
        PFILE_ALL_INFORMATION info = (PFILE_ALL_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
        if (info->StandardInformation.EndOfFile.QuadPart >= WWFLT_HEADER_SIZE) info->StandardInformation.EndOfFile.QuadPart -= WWFLT_HEADER_SIZE;
        else info->StandardInformation.EndOfFile.QuadPart = 0;
        if (info->StandardInformation.AllocationSize.QuadPart >= WWFLT_HEADER_SIZE) info->StandardInformation.AllocationSize.QuadPart -= WWFLT_HEADER_SIZE;
        else info->StandardInformation.AllocationSize.QuadPart = 0;
    } else if (fic == FileNetworkOpenInformation) {
        PFILE_NETWORK_OPEN_INFORMATION info = (PFILE_NETWORK_OPEN_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
        if (info->EndOfFile.QuadPart >= WWFLT_HEADER_SIZE) info->EndOfFile.QuadPart -= WWFLT_HEADER_SIZE;
        else info->EndOfFile.QuadPart = 0;
        if (info->AllocationSize.QuadPart >= WWFLT_HEADER_SIZE) info->AllocationSize.QuadPart -= WWFLT_HEADER_SIZE;
        else info->AllocationSize.QuadPart = 0;
    }
    FltReleaseContext(sctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* IRP_MJ_CLEANUP pre-op: nothing to do (the stream context is freed by
 * the Filter Manager when the stream is torn down). Kept for future use. */
static FLT_PREOP_CALLBACK_STATUS WwPreCleanup(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ------------------------------------------------------------------ */
/* 5. Control device + IOCTL dispatch                                  */
/* ------------------------------------------------------------------ */

static NTSTATUS WwDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS st = STATUS_SUCCESS;
    ULONG in_len, out_len;
    PVOID in_buf, out_buf;
    ULONG code;
    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    in_len = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    out_len = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    in_buf = Irp->AssociatedIrp.SystemBuffer;
    out_buf = Irp->AssociatedIrp.SystemBuffer;

    switch (code) {
    case IOCTL_WWFLT_SET_POLICY: {
        PWWFLT_POLICY new_policy;
        PWWFLT_POLICY old_policy;
        if (in_len < sizeof(WWFLT_POLICY)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        new_policy = (PWWFLT_POLICY)in_buf;
        if (new_policy->proc_count > WWFLT_MAX_PROCESSES) { st = STATUS_INVALID_PARAMETER; break; }
        /* Reject an older policy version (prevents out-of-order updates). */
        ExAcquireResourceExclusiveLite(&gPolicyLock, TRUE);
        if (gPolicy && new_policy->version < gPolicy->version) {
            ExReleaseResourceLite(&gPolicyLock);
            st = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            /* The policy table is only touched at PASSIVE_LEVEL (create
             * path and this IOCTL), so PagedPool is fine and avoids
             * burning ~1MB of non-paged pool. */
            PWWFLT_POLICY copy = (PWWFLT_POLICY)ExAllocatePoolWithTag(PagedPool, sizeof(WWFLT_POLICY), WWFLT_TAG);
            if (!copy) { ExReleaseResourceLite(&gPolicyLock); st = STATUS_INSUFFICIENT_RESOURCES; break; }
            memcpy(copy, new_policy, sizeof(WWFLT_POLICY));
            old_policy = gPolicy;
            gPolicy = copy;
        }
        ExReleaseResourceLite(&gPolicyLock);
        if (old_policy) ExFreePoolWithTag(old_policy, WWFLT_TAG);
        WwLogEvent(WWFLT_EVENT_POLICY, HandleToUlong(PsGetCurrentProcessId()), NULL, NULL, 0, 0, STATUS_SUCCESS);
        break;
    }
    case IOCTL_WWFLT_GET_STATUS: {
        PWWFLT_STATUS s;
        if (out_len < sizeof(WWFLT_STATUS)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        s = (PWWFLT_STATUS)out_buf;
        memset(s, 0, sizeof(*s));
        s->driver_version = 1;
        ExAcquireResourceSharedLite(&gPolicyLock, TRUE);
        s->policy_version = gPolicy ? gPolicy->version : 0;
        ExReleaseResourceLite(&gPolicyLock);
        s->encrypted_files_open = gEncryptedFilesOpen;
        s->bytes_encrypted = gBytesEncrypted;
        s->bytes_decrypted = gBytesDecrypted;
        s->policy_lookups = gPolicyLookups;
        s->io_filtered = gIoFiltered;
        s->errors = gErrors;
        Irp->IoStatus.Information = sizeof(WWFLT_STATUS);
        break;
    }
    case IOCTL_WWFLT_GET_EVENTS: {
        ULONG want;
        ULONG avail;
        ULONG i;
        PWWFLT_EVENT_COUNT hdr_out;
        PWWFLT_EVENT dst;
        KIRQL oldIrql;
        if (in_len < sizeof(ULONG) || out_len < sizeof(WWFLT_EVENT_COUNT)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        want = *(ULONG *)in_buf;
        if (want == 0) want = 64;
        if (want > 1024) want = 1024;
        /* Reserve space for the count header + the events. */
        if (out_len < sizeof(WWFLT_EVENT_COUNT) + want * sizeof(WWFLT_EVENT)) {
            want = (out_len - sizeof(WWFLT_EVENT_COUNT)) / sizeof(WWFLT_EVENT);
        }
        KeAcquireSpinLock(&gEventLock, &oldIrql);
        avail = (ULONG)(gEventWrite - gEventRead);
        if (avail > want) avail = want;
        hdr_out = (PWWFLT_EVENT_COUNT)out_buf;
        hdr_out->count = avail;
        hdr_out->dropped = (ULONG)gEventDropped;
        dst = (PWWFLT_EVENT)((PUCHAR)out_buf + sizeof(WWFLT_EVENT_COUNT));
        for (i = 0; i < avail; i++) {
            LONG idx = (LONG)((gEventRead + (LONGLONG)i) % WWFLT_EVENT_RING_SIZE);
            dst[i] = gEventRing[idx];
        }
        gEventRead += avail;
        KeReleaseSpinLock(&gEventLock, oldIrql);
        Irp->IoStatus.Information = sizeof(WWFLT_EVENT_COUNT) + avail * sizeof(WWFLT_EVENT);
        break;
    }
    case IOCTL_WWFLT_SET_LOG_LEVEL: {
        if (in_len < sizeof(ULONG)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        InterlockedExchange(&gLogLevel, (LONG)*(ULONG *)in_buf);
        break;
    }
    case IOCTL_WWFLT_SET_CONFIG: {
        PWWFLT_CONFIG cfg;
        if (in_len < sizeof(WWFLT_CONFIG)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        cfg = (PWWFLT_CONFIG)in_buf;
        InterlockedExchange(&gEnabled, (LONG)cfg->enabled);
        break;
    }
    default:
        st = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    Irp->IoStatus.Status = st;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

static NTSTATUS WwDeviceCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* 6. DriverEntry / DriverUnload / instance setup                      */
/* ------------------------------------------------------------------ */

static NTSTATUS WwInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    /* Attach to fixed disk volumes with a recognizable filesystem.
     * Skip network / removable / RAW volumes in Phase 1. */
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) return STATUS_FLT_DO_NOT_ATTACH;
    if (VolumeFilesystemType != FLT_FS_NTFS && VolumeFilesystemType != FLT_FS_FAT) return STATUS_FLT_DO_NOT_ATTACH;
    return STATUS_SUCCESS;
}

static NTSTATUS WwInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE, 0, WwPreCreate, WwPostCreate },
    { IRP_MJ_READ, 0, WwPreRead, WwPostRead },
    { IRP_MJ_WRITE, 0, WwPreWrite, WwPostWrite },
    { IRP_MJ_SET_INFORMATION, 0, WwPreSetInfo, NULL },
    { IRP_MJ_QUERY_INFORMATION, 0, NULL, WwPostQueryInfo },
    { IRP_MJ_CLEANUP, 0, WwPreCleanup, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION gFilterReg = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                          /* Flags */
    gContextRegs,               /* ContextRegistration */
    gCallbacks,                 /* OperationRegistration */
    NULL,                       /* FilterUnloadCallback (set below) */
    WwInstanceSetup,            /* InstanceSetupCallback */
    WwInstanceQueryTeardown,    /* InstanceQueryTeardownCallback */
    NULL,                       /* InstanceTeardownStartCallback */
    NULL,                       /* InstanceTeardownCompleteCallback */
    NULL,                       /* GenerateFileNameCallback */
    NULL,                       /* NormalizeNameComponentCallback */
    NULL,                       /* NormalizeContextCleanupCallback */
    NULL,                       /* TransactionNotificationCallback */
    NULL,                       /* NormalizeNameComponentExCallback */
    NULL                        /* SectionNotificationCallback */
};

static NTSTATUS WwFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gControlDevice) {
        UNICODE_STRING sym = RTL_CONSTANT_STRING(WWFLT_DOS_DEVICE_NAME);
        IoDeleteSymbolicLink(&sym);
        IoDeleteDevice(gControlDevice);
        gControlDevice = NULL;
    }
    if (gPolicy) { ExFreePoolWithTag(gPolicy, WWFLT_TAG); gPolicy = NULL; }
    ExDeleteResourceLite(&gPolicyLock);
    ExDeleteNPagedLookasideList(&gSwapLookaside);
    FltUnregisterFilter(gFilter);
    gFilter = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS st;
    UNICODE_STRING dev_name = RTL_CONSTANT_STRING(WWFLT_DEVICE_NAME);
    UNICODE_STRING sym_name = RTL_CONSTANT_STRING(WWFLT_DOS_DEVICE_NAME);
    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeResourceLite(&gPolicyLock);
    KeInitializeSpinLock(&gEventLock);
    ExInitializeNPagedLookasideList(&gSwapLookaside, NULL, NULL, 0, 512, WWFLT_TAG, 0);

    /* Register the filter. The unload callback is patched in via a copy
     * because FLT_REGISTRATION is const here. */
    {
        FLT_REGISTRATION reg = gFilterReg;
        reg.FilterUnloadCallback = WwFilterUnload;
        st = FltRegisterFilter(DriverObject, &reg, &gFilter);
    }
    if (!NT_SUCCESS(st)) {
        ExDeleteResourceLite(&gPolicyLock);
        ExDeleteNPagedLookasideList(&gSwapLookaside);
        return st;
    }
    st = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(st)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        ExDeleteResourceLite(&gPolicyLock);
        ExDeleteNPagedLookasideList(&gSwapLookaside);
        return st;
    }
    /* Control device for the service (IOCTLs). */
    st = IoCreateDevice(DriverObject, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &gControlDevice);
    if (!NT_SUCCESS(st)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        ExDeleteResourceLite(&gPolicyLock);
        ExDeleteNPagedLookasideList(&gSwapLookaside);
        return st;
    }
    st = IoCreateSymbolicLink(&sym_name, &dev_name);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(gControlDevice);
        gControlDevice = NULL;
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        ExDeleteResourceLite(&gPolicyLock);
        ExDeleteNPagedLookasideList(&gSwapLookaside);
        return st;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = WwDeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = WwDeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WwDeviceControl;
    DriverObject->DriverUnload = NULL;  /* minifilter: unload via FltUnregisterFilter */
    return STATUS_SUCCESS;
}
