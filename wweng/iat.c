/* iat.c -- IAT hooking. Walks a module's PE import directory, finds the
 * IAT (FirstThunk) entries for the requested functions, and overwrites
 * them with our replacements (after VirtualProtect to make the page
 * writable). Original addresses are returned via the hook table so the
 * hooks can call through.
 *
 * Matching is by RESOLVED ADDRESS, not by import DLL name. On Windows
 * 10, binaries import CreateFileW/ReadFile/... from API-set DLLs
 * (api-ms-win-core-file-l1-1-0.dll, ...) rather than kernel32.dll,
 * so filtering on dll=="kernel32.dll" silently skips every file-API
 * import -- the hook table only ever matched LoadLibrary-style imports
 * that still name kernel32.dll. The loader resolves an API-set import
 * to the same real address in kernelbase.dll as a kernel32.dll import,
 * so comparing the IAT entry's current value against the known real
 * address (pre-filled in DllMain via GetProcAddress) catches both.
 * A name-based fallback is kept for entries whose original address
 * was never pre-filled.
 */
#include "iat.h"
#include <string.h>
#include <psapi.h>

static HMODULE gOwnModule = NULL;

void WwIatSetOwnModule(HMODULE m) { gOwnModule = m; }

static int CiEqual(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + ('a' - 'A'));
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* Does this import DLL name forward to kernel32 (real name or API set)? */
static int IsKernel32Like(const char *dllName)
{
    if (CiEqual(dllName, "kernel32.dll")) return 1;
    /* API sets that forward kernel32 file/library/handle APIs. */
    if (_strnicmp(dllName, "api-ms-win-core-", 15) == 0) return 1;
    if (_strnicmp(dllName, "api-ms-win-crt-", 14) == 0) return 1;
    return 0;
}

int WwIatHookModule(HMODULE module, const WW_IAT_HOOK *hooks, int nhooks)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_IMPORT_DESCRIPTOR imp;
    int patched = 0;
    int i;

    if (!module || module == gOwnModule) return 0;
    dos = (PIMAGE_DOS_HEADER)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (PIMAGE_NT_HEADERS)((BYTE *)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
        return 0;
    imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)module +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; imp->Name; imp++) {
        const char *dllName = (const char *)((BYTE *)module + imp->Name);
        PIMAGE_THUNK_DATA thunk;
        PIMAGE_THUNK_DATA orig;
        if (!imp->FirstThunk) continue;
        /* Only look at imports that could be kernel32 (real name or
         * API set). This is just a fast pre-filter; the decisive match
         * below is the resolved address / function name. */
        if (!IsKernel32Like(dllName)) continue;
        thunk = (PIMAGE_THUNK_DATA)((BYTE *)module + imp->FirstThunk);
        orig = imp->OriginalFirstThunk
            ? (PIMAGE_THUNK_DATA)((BYTE *)module + imp->OriginalFirstThunk)
            : thunk;
        for (; orig->u1.AddressOfData; orig++, thunk++) {
            PIMAGE_IMPORT_BY_NAME byName;
            const char *funcName;
            void *cur;
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            byName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)module + orig->u1.AddressOfData);
            funcName = (const char *)byName->Name;
            cur = (void *)(ULONG_PTR)thunk->u1.Function;
            for (i = 0; i < nhooks; i++) {
                int match = 0;
                /* Primary: the IAT entry already resolves to the real
                 * function address (pre-filled via GetProcAddress).
                 * This catches API-set imports, whose DLL name is not
                 * kernel32.dll but whose target is identical. */
                if (*hooks[i].original && cur == *hooks[i].original) match = 1;
                /* Fallback: name match (for hooks whose original was
                 * never pre-filled). */
                if (!match && strcmp(funcName, hooks[i].func) == 0) match = 1;
                if (!match) continue;
                if (!*hooks[i].original) {
                    *hooks[i].original = cur;
                }
                if (cur != hooks[i].replacement) {
                    DWORD oldProt;
                    if (VirtualProtect(&thunk->u1.Function, sizeof(void *),
                                       PAGE_READWRITE, &oldProt)) {
                        thunk->u1.Function = (ULONGLONG)(ULONG_PTR)hooks[i].replacement;
                        VirtualProtect(&thunk->u1.Function, sizeof(void *),
                                       oldProt, &oldProt);
                        patched++;
                    }
                }
            }
        }
    }
    return patched;
}

int WwIatHookAllModules(const WW_IAT_HOOK *hooks, int nhooks)
{
    HMODULE mods[512];
    DWORD needed = 0;
    DWORD count, i;
    int total = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return 0;
    count = needed / sizeof(HMODULE);
    if (count > 512) count = 512;
    for (i = 0; i < count; i++) {
        total += WwIatHookModule(mods[i], hooks, nhooks);
    }
    return total;
}
