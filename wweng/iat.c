/* iat.c -- IAT hooking. Walks a module's PE import directory, finds the
 * IAT (FirstThunk) entries for the requested DLL/function pairs, and
 * overwrites them with our replacements (after VirtualProtect to make
 * the page writable). Original addresses are returned via the hook
 * table so the hooks can call through.
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
        /* Only patch imports from a DLL we have hooks for. */
        {
            int want = 0;
            for (i = 0; i < nhooks; i++) {
                if (CiEqual(dllName, hooks[i].dll)) { want = 1; break; }
            }
            if (!want) continue;
        }
        thunk = (PIMAGE_THUNK_DATA)((BYTE *)module + imp->FirstThunk);
        orig = imp->OriginalFirstThunk
            ? (PIMAGE_THUNK_DATA)((BYTE *)module + imp->OriginalFirstThunk)
            : thunk;
        for (; orig->u1.AddressOfData; orig++, thunk++) {
            PIMAGE_IMPORT_BY_NAME byName;
            const char *funcName;
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            byName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)module + orig->u1.AddressOfData);
            funcName = (const char *)byName->Name;
            for (i = 0; i < nhooks; i++) {
                if (!CiEqual(dllName, hooks[i].dll)) continue;
                if (strcmp(funcName, hooks[i].func) != 0) continue;
                if (!*hooks[i].original) {
                    *hooks[i].original = (void *)(ULONG_PTR)thunk->u1.Function;
                }
                if ((void *)(ULONG_PTR)thunk->u1.Function != hooks[i].replacement) {
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
