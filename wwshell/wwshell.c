/* wwshell.c -- shell extension for the new WaterWall client.
 * Two COM classes, pure Win32 + hand-written COM (no ATL):
 *   - CWWShellIcon: IShellIconOverlayIdentifier, lock overlay on encrypted files.
 *   - CWWShellMenu: IShellExtInit + IContextMenu, right-click Encrypt / Direct Decrypt.
 *
 * This is a clean-room reimplementation. The vendor's wwshell64.dll cannot
 * be reused: it asks the WWHost driver and wwkrn64.dll whether a file is
 * encrypted, and its menu actions shell out to vendor helper EXEs
 * (wwencrpt.exe / wwdecrpt.exe / wwflwask.exe). None of those exist in
 * the new client. Our version detects encryption by reading the file
 * header directly (the same 512-byte header the engine uses) and does
 * the encrypt/decrypt conversion inside the DLL, reusing the engine's
 * sbox + header code.
 *
 * Decisions (user, 2026-11-13): lock icon = the supplied Project1.ico;
 * flow-decrypt NOT implemented; publish / send-mail NOT implemented;
 * fresh GUIDs (do not reuse the vendor's CLSIDs).
 *
 * Build: zig cc -target x86_64-windows-gnu (wwshell64.dll) and
 * i386-windows-gnu (wwshell.dll). Register with regsvr32; Explorer
 * must restart to pick up the overlay.
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- our own GUIDs (fresh, generated 2026-11-13) ---- */
static const GUID CLSID_WWShellIcon =
    { 0xD5E185D5, 0x4E2E, 0x4AC4, { 0xB0, 0x99, 0x93, 0xAC, 0x03, 0x39, 0x18, 0x49 } };
static const GUID CLSID_WWShellMenu =
    { 0x46B42114, 0xA904, 0x4693, { 0x90, 0x5F, 0x31, 0xAA, 0x93, 0x29, 0x52, 0xC3 } };

/* Interface IDs come from the system headers (shlobj.h). */

/* ---- file format constants (same as the engine, wwflt.h) ---- */
#define WW_HDR_SIZE     512
#define WW_KEY_SIZE     32
#define WW_MAGIC_SIZE   16
#define WW_VER_OFF      0x10
#define WW_POLICY_OFF   0x12
#define WW_KEY_OFF      0x30
#define WW_VERSION_1    1
#define WW_VERSION_2    2
#define WW_CUR_VERSION  WW_VERSION_2

static const unsigned char gMagic[WW_MAGIC_SIZE] =
    { 0x40,0x21,0x28,0x15,0x2a,0x2d,0x1b,0x20,
      0x23,0x30,0x1e,0x19,0x2f,0x22,0x16,0x40 };

/* ---- sbox (from ../wweng/sbox.c, same cipher as the engine) ---- */
#include "../wweng/sbox.h"

static HMODULE g_hModule = NULL;
static LONG g_dllLocks = 0;

/* ---- header build / parse (same logic as the engine's policy.c) ---- */
static void WwShellBuildHeader(unsigned char hdr[WW_HDR_SIZE],
                               const char *policy_name,
                               const unsigned char key[WW_KEY_SIZE])
{
    WW_SBOX_CTX tmp;
    size_t pn_len;
    memset(hdr, 0, WW_HDR_SIZE);
    memcpy(hdr, gMagic, WW_MAGIC_SIZE);
    hdr[WW_VER_OFF] = (unsigned char)(WW_CUR_VERSION & 0xff);
    hdr[WW_VER_OFF + 1] = (unsigned char)((WW_CUR_VERSION >> 8) & 0xff);
    pn_len = strlen(policy_name);
    if (pn_len > (size_t)(WW_HDR_SIZE - WW_POLICY_OFF - 1))
        pn_len = WW_HDR_SIZE - WW_POLICY_OFF - 1;
    memcpy(hdr + WW_POLICY_OFF, policy_name, pn_len);
    memcpy(hdr + WW_KEY_OFF, key, WW_KEY_SIZE);
    /* Encrypt +0x12..0x30 and +0x50..0x1ff, counter = offset-0x12.
     * The key at +0x30..0x4f stays PLAINTEXT. */
    WwSboxInit(&tmp, WW_CUR_VERSION, key);
    WwSboxEncrypt(&tmp, hdr + WW_POLICY_OFF, WW_KEY_OFF - WW_POLICY_OFF, 0);
    WwSboxEncrypt(&tmp, hdr + WW_KEY_OFF + WW_KEY_SIZE,
                  WW_HDR_SIZE - (WW_KEY_OFF + WW_KEY_SIZE),
                  WW_KEY_OFF + WW_KEY_SIZE - WW_POLICY_OFF);
}

static BOOL WwShellParseHeader(unsigned char hdr[WW_HDR_SIZE],
                               unsigned char key[WW_KEY_SIZE], int *version)
{
    WW_SBOX_CTX tmp;
    if (memcmp(hdr, gMagic, WW_MAGIC_SIZE) != 0) return FALSE;
    *version = hdr[WW_VER_OFF] | (hdr[WW_VER_OFF + 1] << 8);
    if (*version != WW_VERSION_1 && *version != WW_VERSION_2) return FALSE;
    memcpy(key, hdr + WW_KEY_OFF, WW_KEY_SIZE);
    WwSboxInit(&tmp, *version, key);
    WwSboxDecrypt(&tmp, hdr + WW_POLICY_OFF, WW_KEY_OFF - WW_POLICY_OFF, 0);
    WwSboxDecrypt(&tmp, hdr + WW_KEY_OFF + WW_KEY_SIZE,
                  WW_HDR_SIZE - (WW_KEY_OFF + WW_KEY_SIZE),
                  WW_KEY_OFF + WW_KEY_SIZE - WW_POLICY_OFF);
    return TRUE;
}

typedef BOOLEAN (WINAPI *RtlGenRandom_t)(PVOID, ULONG);

static void WwShellRandomKey(unsigned char key[WW_KEY_SIZE])
{
    static RtlGenRandom_t fn = NULL;
    if (!fn) {
        HMODULE adv = GetModuleHandleW(L"advapi32.dll");
        if (adv) fn = (RtlGenRandom_t)GetProcAddress(adv, "SystemFunction036");
    }
    if (fn && fn(key, WW_KEY_SIZE)) return;
    {
        unsigned i;
        srand(GetTickCount() ^ GetCurrentProcessId());
        for (i = 0; i < WW_KEY_SIZE; i++) key[i] = (unsigned char)(rand() & 0xff);
    }
}

/* ---- encrypted-extension list (from the vendor's wwshell.xcf,
 * encrypt_icon_files; the same list gates both the overlay and the
 * Encrypt menu item) ---- */
static const WCHAR *gEncExts[] = {
    L"exb", L"pdf", L"jpg", L"jpeg", L"gif", L"bmp", L"rtf", L"txt",
    L"doc", L"xls", L"ppt", L"docx", L"xlsx", L"pptx", L"wps", L"et",
    L"dps", L"vsd", L"mpp", L"psd", L"cdr", L"dwg", L"dxf", L"dwf",
    L"asm", L"prt", L"sldasm", L"sldprt", L"idw", L"ipt", L"iam",
    L"catproduct", L"catpart", L"igs", L"iges", L"stp", L"step",
    L"max", L"sch", L"schdoc", NULL
};

static BOOL ExtInList(const WCHAR *path)
{
    const WCHAR *dot = wcsrchr(path, L'.');
    const WCHAR *slash = wcsrchr(path, L'\\');
    int i;
    if (!dot || (slash && dot < slash)) return FALSE;
    dot++;
    for (i = 0; gEncExts[i]; i++) {
        if (_wcsicmp(dot, gEncExts[i]) == 0) return TRUE;
    }
    return FALSE;
}

/* Is this file encrypted? Extension must be in the list AND the
 * 512-byte header must verify (magic + known version). Reads only
 * the header; never touches the content. */
static BOOL IsEncryptedFile(const WCHAR *path)
{
    HANDLE h;
    unsigned char hdr[WW_HDR_SIZE];
    DWORD read = 0;
    unsigned char key[WW_KEY_SIZE];
    int version = 0;
    if (!ExtInList(path)) return FALSE;
    h = CreateFileW(path, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!ReadFile(h, hdr, WW_HDR_SIZE, &read, NULL) || read < WW_HDR_SIZE) {
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);
    return WwShellParseHeader(hdr, key, &version);
}

/* ---- file conversion (streaming, temp file + replace) ----
 * Encrypt: plaintext -> 512-byte header + ciphertext.
 * Decrypt: 512-byte header + ciphertext -> plaintext.
 * Both write to a temp file in the same directory and replace the
 * original only on success, so a failure never truncates the
 * original. File times are preserved. */
#define WW_CHUNK 65536

static BOOL PreserveTimes(const WCHAR *src, const WCHAR *dst)
{
    HANDLE hs, hd;
    FILETIME ct, at, wt;
    BOOL ok = FALSE;
    hs = CreateFileW(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                     NULL, OPEN_EXISTING, 0, NULL);
    if (hs == INVALID_HANDLE_VALUE) return FALSE;
    if (GetFileTime(hs, &ct, &at, &wt)) {
        hd = CreateFileW(dst, FILE_WRITE_ATTRIBUTES, 0, NULL,
                         OPEN_EXISTING, 0, NULL);
        if (hd != INVALID_HANDLE_VALUE) {
            ok = SetFileTime(hd, &ct, &at, &wt);
            CloseHandle(hd);
        }
    }
    CloseHandle(hs);
    return ok;
}

static BOOL WwEncryptFile(const WCHAR *path)
{
    HANDLE hin = INVALID_HANDLE_VALUE, hout = INVALID_HANDLE_VALUE;
    WCHAR tmp[MAX_PATH], dir[MAX_PATH], *slash;
    unsigned char key[WW_KEY_SIZE];
    unsigned char hdr[WW_HDR_SIZE];
    WW_SBOX_CTX sbox;
    unsigned char *buf = NULL;
    ULONGLONG logical = 0;
    DWORD read = 0, written = 0;
    BOOL ok = FALSE;

    wcsncpy(dir, path, MAX_PATH - 1);
    dir[MAX_PATH - 1] = L'\0';
    slash = wcsrchr(dir, L'\\');
    if (!slash) return FALSE;
    *slash = L'\0';
    if (!GetTempFileNameW(dir, L"wwe", 0, tmp)) return FALSE;

    hin = CreateFileW(path, GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hin == INVALID_HANDLE_VALUE) goto done;
    hout = CreateFileW(tmp, GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hout == INVALID_HANDLE_VALUE) goto done;
    buf = (unsigned char *)malloc(WW_CHUNK);
    if (!buf) goto done;

    WwShellRandomKey(key);
    WwShellBuildHeader(hdr, "EXPLORER.", key);
    if (!WriteFile(hout, hdr, WW_HDR_SIZE, &written, NULL) ||
        written != WW_HDR_SIZE) goto done;
    WwSboxInit(&sbox, WW_CUR_VERSION, key);
    for (;;) {
        if (!ReadFile(hin, buf, WW_CHUNK, &read, NULL)) goto done;
        if (read == 0) break;
        WwSboxEncrypt(&sbox, buf, read, logical);
        logical += read;
        if (!WriteFile(hout, buf, read, &written, NULL) ||
            written != read) goto done;
    }
    ok = TRUE;
done:
    if (buf) free(buf);
    if (hin != INVALID_HANDLE_VALUE) CloseHandle(hin);
    if (hout != INVALID_HANDLE_VALUE) CloseHandle(hout);
    if (ok) {
        PreserveTimes(path, tmp);
        if (!MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING)) ok = FALSE;
    }
    if (!ok) DeleteFileW(tmp);
    return ok;
}

static BOOL WwDecryptFile(const WCHAR *path)
{
    HANDLE hin = INVALID_HANDLE_VALUE, hout = INVALID_HANDLE_VALUE;
    WCHAR tmp[MAX_PATH], dir[MAX_PATH], *slash;
    unsigned char key[WW_KEY_SIZE];
    unsigned char hdr[WW_HDR_SIZE];
    WW_SBOX_CTX sbox;
    unsigned char *buf = NULL;
    int version = 0;
    ULONGLONG logical = 0;
    DWORD read = 0, written = 0;
    BOOL ok = FALSE;

    wcsncpy(dir, path, MAX_PATH - 1);
    dir[MAX_PATH - 1] = L'\0';
    slash = wcsrchr(dir, L'\\');
    if (!slash) return FALSE;
    *slash = L'\0';
    if (!GetTempFileNameW(dir, L"wwd", 0, tmp)) return FALSE;

    hin = CreateFileW(path, GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hin == INVALID_HANDLE_VALUE) goto done;
    if (!ReadFile(hin, hdr, WW_HDR_SIZE, &read, NULL) ||
        read != WW_HDR_SIZE) goto done;
    if (!WwShellParseHeader(hdr, key, &version)) goto done;
    hout = CreateFileW(tmp, GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hout == INVALID_HANDLE_VALUE) goto done;
    buf = (unsigned char *)malloc(WW_CHUNK);
    if (!buf) goto done;

    WwSboxInit(&sbox, version, key);
    for (;;) {
        if (!ReadFile(hin, buf, WW_CHUNK, &read, NULL)) goto done;
        if (read == 0) break;
        WwSboxDecrypt(&sbox, buf, read, logical);
        logical += read;
        if (!WriteFile(hout, buf, read, &written, NULL) ||
            written != read) goto done;
    }
    ok = TRUE;
done:
    if (buf) free(buf);
    if (hin != INVALID_HANDLE_VALUE) CloseHandle(hin);
    if (hout != INVALID_HANDLE_VALUE) CloseHandle(hout);
    if (ok) {
        PreserveTimes(path, tmp);
        if (!MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING)) ok = FALSE;
    }
    if (!ok) DeleteFileW(tmp);
    return ok;
}

/* ---- COM base ---- */
typedef struct {
    const void *lpVtbl;
    LONG ref;
} WwComBase;

static ULONG WwComAddRef(WwComBase *b)
{
    return (ULONG)InterlockedIncrement(&b->ref);
}

static ULONG WwComRelease(WwComBase *b)
{
    LONG r = InterlockedDecrement(&b->ref);
    if (r == 0) free(b);
    return (ULONG)r;
}

/* ---- IShellIconOverlayIdentifier vtable ---- */
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *self, REFIID riid, void **ppv);
    ULONG (STDMETHODCALLTYPE *AddRef)(void *self);
    ULONG (STDMETHODCALLTYPE *Release)(void *self);
    HRESULT (STDMETHODCALLTYPE *IsMemberOf)(void *self, LPCWSTR pszPath, DWORD dwAttrib);
    HRESULT (STDMETHODCALLTYPE *GetOverlayInfo)(void *self, LPWSTR pwszIconFile, int cchMax, int *pIndex, DWORD *pdwFlags);
    HRESULT (STDMETHODCALLTYPE *GetPriority)(void *self, int *pPriority);
} WwIconVtbl;

typedef struct {
    const WwIconVtbl *lpVtbl;
    LONG ref;
} WwShellIcon;

static HRESULT STDMETHODCALLTYPE Icon_QueryInterface(void *self, REFIID riid, void **ppv)
{
    WwShellIcon *o = (WwShellIcon *)self;
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IShellIconOverlayIdentifier)) {
        *ppv = o;
        InterlockedIncrement(&o->ref);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Icon_AddRef(void *self)
{
    return WwComAddRef((WwComBase *)self);
}

static ULONG STDMETHODCALLTYPE Icon_Release(void *self)
{
    return WwComRelease((WwComBase *)self);
}

static HRESULT STDMETHODCALLTYPE Icon_IsMemberOf(void *self, LPCWSTR pszPath, DWORD dwAttrib)
{
    (void)self;
    if (dwAttrib & FILE_ATTRIBUTE_DIRECTORY) return S_FALSE;
    return IsEncryptedFile(pszPath) ? S_OK : S_FALSE;
}

static HRESULT STDMETHODCALLTYPE Icon_GetOverlayInfo(void *self, LPWSTR pwszIconFile,
                                                     int cchMax, int *pIndex, DWORD *pdwFlags)
{
    (void)self;
    if (!pwszIconFile || !pIndex || !pdwFlags) return E_POINTER;
    if (!GetModuleFileNameW(g_hModule, pwszIconFile, (DWORD)cchMax)) return E_FAIL;
    *pIndex = 0;
    *pdwFlags = ISIOI_ICONFILE | ISIOI_ICONINDEX;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Icon_GetPriority(void *self, int *pPriority)
{
    (void)self;
    if (!pPriority) return E_POINTER;
    *pPriority = 0;
    return S_OK;
}

static const WwIconVtbl g_IconVtbl = {
    Icon_QueryInterface, Icon_AddRef, Icon_Release,
    Icon_IsMemberOf, Icon_GetOverlayInfo, Icon_GetPriority
};

/* ---- IContextMenu + IShellExtInit vtable ---- */
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *self, REFIID riid, void **ppv);
    ULONG (STDMETHODCALLTYPE *AddRef)(void *self);
    ULONG (STDMETHODCALLTYPE *Release)(void *self);
    HRESULT (STDMETHODCALLTYPE *QueryContextMenu)(void *self, HMENU hmenu, UINT indexMenu,
                                                  UINT idCmdFirst, UINT idCmdLast, UINT uFlags);
    HRESULT (STDMETHODCALLTYPE *InvokeCommand)(void *self, LPCMINVOKECOMMANDINFO pici);
    HRESULT (STDMETHODCALLTYPE *GetCommandString)(void *self, UINT_PTR idCmd, UINT uType,
                                                  UINT *pReserved, LPSTR pszName, UINT cchMax);
} WwMenuVtbl;

typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *self, REFIID riid, void **ppv);
    ULONG (STDMETHODCALLTYPE *AddRef)(void *self);
    ULONG (STDMETHODCALLTYPE *Release)(void *self);
    HRESULT (STDMETHODCALLTYPE *Initialize)(void *self, LPCITEMIDLIST pidlFolder,
                                            IDataObject *pDataObj, HKEY hkeyProgID);
} WwInitVtbl;

#define WW_MAX_FILES 64

typedef struct {
    const WwMenuVtbl *lpVtbl;       /* IContextMenu, offset 0 (primary) */
    const WwInitVtbl *lpVtblInit;   /* IShellExtInit, offset sizeof(void*) */
    LONG ref;
    int nfiles;
    WCHAR files[WW_MAX_FILES][MAX_PATH];
    /* command offsets assigned in QueryContextMenu (relative to idCmdFirst) */
    int cmdDecrypt;  /* -1 if not shown */
    int cmdEncrypt;  /* -1 if not shown */
} WwShellMenu;

#define MENU_FROM_INIT(p) ((WwShellMenu *)((BYTE *)(p) - offsetof(WwShellMenu, lpVtblInit)))

static HRESULT STDMETHODCALLTYPE Menu_QueryInterface(void *self, REFIID riid, void **ppv)
{
    WwShellMenu *o = (WwShellMenu *)self;
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IContextMenu)) {
        *ppv = o;
        InterlockedIncrement(&o->ref);
        return S_OK;
    }
    if (IsEqualIID(riid, &IID_IShellExtInit)) {
        /* IShellExtInit lives at offsetof(WwShellMenu, lpVtblInit). */
        *ppv = (void *)&o->lpVtblInit;
        InterlockedIncrement(&o->ref);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static HRESULT STDMETHODCALLTYPE MenuInit_QueryInterface(void *self, REFIID riid, void **ppv)
{
    WwShellMenu *o = MENU_FROM_INIT(self);
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IShellExtInit)) {
        *ppv = self;
        InterlockedIncrement(&o->ref);
        return S_OK;
    }
    /* IShellExtInit also answers IContextMenu (same object). */
    return Menu_QueryInterface(o, riid, ppv);
}

static ULONG STDMETHODCALLTYPE Menu_AddRef(void *self)
{
    return WwComAddRef((WwComBase *)self);
}

static ULONG STDMETHODCALLTYPE Menu_Release(void *self)
{
    return WwComRelease((WwComBase *)self);
}

static ULONG STDMETHODCALLTYPE MenuInit_AddRef(void *self)
{
    return WwComAddRef((WwComBase *)MENU_FROM_INIT(self));
}

static ULONG STDMETHODCALLTYPE MenuInit_Release(void *self)
{
    return WwComRelease((WwComBase *)MENU_FROM_INIT(self));
}

static HRESULT STDMETHODCALLTYPE Menu_Initialize(void *self, LPCITEMIDLIST pidlFolder,
                                                 IDataObject *pDataObj, HKEY hkeyProgID)
{
    WwShellMenu *o = MENU_FROM_INIT(self);
    FORMATETC fmt = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    STGMEDIUM stg;
    HDROP hdrop;
    UINT i, n;
    (void)pidlFolder;
    (void)hkeyProgID;
    o->nfiles = 0;
    o->cmdDecrypt = -1;
    o->cmdEncrypt = -1;
    if (!pDataObj) return S_OK;
    if (pDataObj->lpVtbl->GetData(pDataObj, &fmt, &stg) != S_OK) return S_OK;
    hdrop = (HDROP)stg.hGlobal;
    if (!hdrop) return S_OK;
    n = DragQueryFileW(hdrop, 0xFFFFFFFF, NULL, 0);
    if (n > WW_MAX_FILES) n = WW_MAX_FILES;
    for (i = 0; i < n; i++) {
        if (DragQueryFileW(hdrop, i, o->files[o->nfiles], MAX_PATH) > 0)
            o->nfiles++;
    }
    ReleaseStgMedium(&stg);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Menu_QueryContextMenu(void *self, HMENU hmenu, UINT indexMenu,
                                                       UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
    WwShellMenu *o = (WwShellMenu *)self;
    int i, added = 0;
    BOOL anyEncrypted = FALSE, anyPlain = FALSE;
    (void)idCmdLast;
    if (!hmenu) return E_POINTER;
    if (o->nfiles == 0) return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
    if (uFlags & CMF_DEFAULTONLY) return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
    for (i = 0; i < o->nfiles; i++) {
        DWORD attr = GetFileAttributesW(o->files[i]);
        if (attr == INVALID_FILE_ATTRIBUTES ||
            (attr & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (IsEncryptedFile(o->files[i])) anyEncrypted = TRUE;
        else if (ExtInList(o->files[i])) anyPlain = TRUE;
    }
    o->cmdDecrypt = -1;
    o->cmdEncrypt = -1;
    if (anyEncrypted) {
        o->cmdDecrypt = added;
        InsertMenuW(hmenu, indexMenu + added, MF_STRING | MF_BYPOSITION,
                    idCmdFirst + added, L"直接解密文件");
        added++;
    }
    if (anyPlain) {
        o->cmdEncrypt = added;
        InsertMenuW(hmenu, indexMenu + added, MF_STRING | MF_BYPOSITION,
                    idCmdFirst + added, L"手动加密文件");
        added++;
    }
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, added);
}

static HRESULT STDMETHODCALLTYPE Menu_InvokeCommand(void *self, LPCMINVOKECOMMANDINFO pici)
{
    WwShellMenu *o = (WwShellMenu *)self;
    int i, ok = 0, fail = 0, total = 0;
    int cmd;
    if (!pici) return E_POINTER;
    if (HIWORD(pici->lpVerb) != 0) return E_FAIL;
    cmd = LOWORD(pici->lpVerb);
    for (i = 0; i < o->nfiles; i++) {
        BOOL done = FALSE;
        if (cmd == o->cmdDecrypt && o->cmdDecrypt >= 0) {
            if (IsEncryptedFile(o->files[i])) {
                total++;
                done = WwDecryptFile(o->files[i]);
            }
        } else if (cmd == o->cmdEncrypt && o->cmdEncrypt >= 0) {
            if (!IsEncryptedFile(o->files[i]) && ExtInList(o->files[i])) {
                total++;
                done = WwEncryptFile(o->files[i]);
            }
        }
        if (total > 0 && done) ok++;
        else if (total > 0) fail++;
        /* files that don't match the command are skipped, not counted */
        if (cmd != o->cmdDecrypt && cmd != o->cmdEncrypt) break;
    }
    if (total == 0) return S_OK;
    if (fail > 0) {
        WCHAR msg[256];
        swprintf(msg, 256, L"完成 %d 个，失败 %d 个。", ok, fail);
        MessageBoxW(pici->hwnd, msg, L"WaterWall", MB_OK | MB_ICONWARNING);
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Menu_GetCommandString(void *self, UINT_PTR idCmd, UINT uType,
                                                       UINT *pReserved, LPSTR pszName, UINT cchMax)
{
    WwShellMenu *o = (WwShellMenu *)self;
    const char *help = NULL;
    (void)pReserved;
    if (uType != GCS_HELPTEXTA && uType != GCS_HELPTEXTW) return E_INVALIDARG;
    if ((int)idCmd == o->cmdDecrypt) help = "直接解密选中的文件";
    else if ((int)idCmd == o->cmdEncrypt) help = "手动加密选中的文件";
    else return E_INVALIDARG;
    if (uType == GCS_HELPTEXTW) {
        MultiByteToWideChar(CP_UTF8, 0, help, -1, (LPWSTR)pszName, cchMax);
    } else {
        strncpy(pszName, help, cchMax);
        pszName[cchMax - 1] = '\0';
    }
    return S_OK;
}

static const WwMenuVtbl g_MenuVtbl = {
    Menu_QueryInterface, Menu_AddRef, Menu_Release,
    Menu_QueryContextMenu, Menu_InvokeCommand, Menu_GetCommandString
};

static const WwInitVtbl g_InitVtbl = {
    MenuInit_QueryInterface, MenuInit_AddRef, MenuInit_Release,
    Menu_Initialize
};

/* ---- class factory ---- */
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *self, REFIID riid, void **ppv);
    ULONG (STDMETHODCALLTYPE *AddRef)(void *self);
    ULONG (STDMETHODCALLTYPE *Release)(void *self);
    HRESULT (STDMETHODCALLTYPE *CreateInstance)(void *self, IUnknown *pUnkOuter,
                                                REFIID riid, void **ppv);
    HRESULT (STDMETHODCALLTYPE *LockServer)(void *self, BOOL fLock);
} WwFactoryVtbl;

typedef struct {
    const WwFactoryVtbl *lpVtbl;
    LONG ref;
    const GUID *clsid;
} WwClassFactory;

static HRESULT STDMETHODCALLTYPE Factory_QueryInterface(void *self, REFIID riid, void **ppv)
{
    WwClassFactory *o = (WwClassFactory *)self;
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IClassFactory)) {
        *ppv = o;
        InterlockedIncrement(&o->ref);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Factory_AddRef(void *self)
{
    return WwComAddRef((WwComBase *)self);
}

static ULONG STDMETHODCALLTYPE Factory_Release(void *self)
{
    return WwComRelease((WwComBase *)self);
}

static HRESULT STDMETHODCALLTYPE Factory_CreateInstance(void *self, IUnknown *pUnkOuter,
                                                        REFIID riid, void **ppv)
{
    WwClassFactory *o = (WwClassFactory *)self;
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (pUnkOuter) return CLASS_E_NOAGGREGATION;
    if (IsEqualGUID(o->clsid, &CLSID_WWShellIcon)) {
        WwShellIcon *icon = (WwShellIcon *)calloc(1, sizeof(WwShellIcon));
        HRESULT hr;
        if (!icon) return E_OUTOFMEMORY;
        icon->lpVtbl = &g_IconVtbl;
        icon->ref = 1;
        hr = Icon_QueryInterface(icon, riid, ppv);
        Icon_Release(icon);
        return hr;
    }
    if (IsEqualGUID(o->clsid, &CLSID_WWShellMenu)) {
        WwShellMenu *menu = (WwShellMenu *)calloc(1, sizeof(WwShellMenu));
        HRESULT hr;
        if (!menu) return E_OUTOFMEMORY;
        menu->lpVtbl = &g_MenuVtbl;
        menu->lpVtblInit = &g_InitVtbl;
        menu->ref = 1;
        menu->cmdDecrypt = -1;
        menu->cmdEncrypt = -1;
        hr = Menu_QueryInterface(menu, riid, ppv);
        Menu_Release(menu);
        return hr;
    }
    return E_NOINTERFACE;
}

static HRESULT STDMETHODCALLTYPE Factory_LockServer(void *self, BOOL fLock)
{
    (void)self;
    if (fLock) InterlockedIncrement(&g_dllLocks);
    else InterlockedDecrement(&g_dllLocks);
    return S_OK;
}

static const WwFactoryVtbl g_FactoryVtbl = {
    Factory_QueryInterface, Factory_AddRef, Factory_Release,
    Factory_CreateInstance, Factory_LockServer
};

/* ---- DLL exports ---- */
HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv)
{
    WwClassFactory *f;
    HRESULT hr;
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (!IsEqualGUID(rclsid, &CLSID_WWShellIcon) &&
        !IsEqualGUID(rclsid, &CLSID_WWShellMenu))
        return CLASS_E_CLASSNOTAVAILABLE;
    f = (WwClassFactory *)calloc(1, sizeof(WwClassFactory));
    if (!f) return E_OUTOFMEMORY;
    f->lpVtbl = &g_FactoryVtbl;
    f->ref = 1;
    f->clsid = IsEqualGUID(rclsid, &CLSID_WWShellIcon) ? &CLSID_WWShellIcon : &CLSID_WWShellMenu;
    hr = Factory_QueryInterface(f, riid, ppv);
    Factory_Release(f);
    return hr;
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    return g_dllLocks == 0 ? S_OK : S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hModule = (HMODULE)hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

/* ---- registration ---- */
static void GuidString(const GUID *g, WCHAR *out, size_t chars)
{
    swprintf(out, chars,
             L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             g->Data1, g->Data2, g->Data3,
             g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
             g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

static BOOL RegSetStr(HKEY root, const WCHAR *sub, const WCHAR *valname, const WCHAR *val)
{
    HKEY h;
    LONG r = RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_WRITE, NULL, &h, NULL);
    if (r != ERROR_SUCCESS) return FALSE;
    r = RegSetValueExW(h, valname, 0, REG_SZ, (const BYTE *)val,
                       (DWORD)((wcslen(val) + 1) * sizeof(WCHAR)));
    RegCloseKey(h);
    return r == ERROR_SUCCESS;
}

static void RegDelTree(HKEY root, const WCHAR *sub)
{
    RegDeleteTreeW(root, sub);
}

/* Overlay name with 10 leading spaces, like the vendor: Windows shows
 * only the first 15 overlay handlers, sorted by this key name, so a
 * leading-space name sorts to the front. */
#define WW_OVERLAY_NAME L"          WWShellIcon"

static HRESULT WwRegisterClass(const GUID *clsid, const WCHAR *desc,
                             const WCHAR *progid)
{
    WCHAR guid[40], key[MAX_PATH], dllpath[MAX_PATH];
    GuidString(clsid, guid, 40);
    if (!GetModuleFileNameW(g_hModule, dllpath, MAX_PATH)) return E_FAIL;
    swprintf(key, MAX_PATH, L"CLSID\\%s", guid);
    if (!RegSetStr(HKEY_CLASSES_ROOT, key, NULL, desc)) return E_FAIL;
    swprintf(key, MAX_PATH, L"CLSID\\%s\\InprocServer32", guid);
    if (!RegSetStr(HKEY_CLASSES_ROOT, key, NULL, dllpath)) return E_FAIL;
    if (!RegSetStr(HKEY_CLASSES_ROOT, key, L"ThreadingModel", L"Apartment")) return E_FAIL;
    if (!RegSetStr(HKEY_CLASSES_ROOT, progid, NULL, desc)) return E_FAIL;
    swprintf(key, MAX_PATH, L"%s\\CLSID", progid);
    if (!RegSetStr(HKEY_CLASSES_ROOT, key, NULL, guid)) return E_FAIL;
    return S_OK;
}

static void WwUnregisterClass(const GUID *clsid, const WCHAR *progid)
{
    WCHAR guid[40], key[MAX_PATH];
    GuidString(clsid, guid, 40);
    swprintf(key, MAX_PATH, L"CLSID\\%s", guid);
    RegDelTree(HKEY_CLASSES_ROOT, key);
    RegDelTree(HKEY_CLASSES_ROOT, progid);
}

HRESULT WINAPI DllRegisterServer(void)
{
    WCHAR guid[40];
    HRESULT hr;
    hr = WwRegisterClass(&CLSID_WWShellIcon, L"WWShellIcon Class",
                       L"WWShell.WWShellIcon.1");
    if (FAILED(hr)) return hr;
    hr = WwRegisterClass(&CLSID_WWShellMenu, L"WWShellMenu Class",
                       L"WWShell.WWShellMenu.1");
    if (FAILED(hr)) return hr;
    /* Overlay identifier: a SUBKEY named '          WWShellIcon' under
     * ShellIconOverlayIdentifiers, whose default value is the CLSID.
     * (Explorer enumerates subkeys, not values -- writing it as a value
     * is silently ignored, which is why the icon never appeared.) */
    {
        WCHAR overlayKey[MAX_PATH];
        swprintf(overlayKey, MAX_PATH,
                 L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\%s",
                 WW_OVERLAY_NAME);
        GuidString(&CLSID_WWShellIcon, guid, 40);
        if (!RegSetStr(HKEY_LOCAL_MACHINE, overlayKey, NULL, guid)) {
            /* Fall back to the per-user location if HKLM is not writable. */
            if (!RegSetStr(HKEY_CURRENT_USER, overlayKey, NULL, guid))
                return E_FAIL;
        }
    }
    /* Context menu handler for all files. */
    GuidString(&CLSID_WWShellMenu, guid, 40);
    if (!RegSetStr(HKEY_CLASSES_ROOT,
                   L"*\\shellex\\ContextMenuHandlers\\WWShellMenu", NULL, guid))
        return E_FAIL;
    return S_OK;
}

HRESULT WINAPI DllUnregisterServer(void)
{
    WCHAR key[MAX_PATH];
    WwUnregisterClass(&CLSID_WWShellIcon, L"WWShell.WWShellIcon.1");
    WwUnregisterClass(&CLSID_WWShellMenu, L"WWShell.WWShellMenu.1");
    swprintf(key, MAX_PATH,
             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\%s",
             WW_OVERLAY_NAME);
    RegDelTree(HKEY_LOCAL_MACHINE, key);
    RegDelTree(HKEY_CURRENT_USER, key);
    RegDelTree(HKEY_CLASSES_ROOT, L"*\\shellex\\ContextMenuHandlers\\WWShellMenu");
    return S_OK;
}
