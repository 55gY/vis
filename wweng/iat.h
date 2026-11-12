/* iat.h -- IAT (Import Address Table) hooking for the engine DLL.
 * Replaces, in every loaded module (except our own), the IAT entries for
 * the file APIs we intercept, so calls made through the IAT reach our
 * hooks. Also patches LoadLibrary so modules loaded later get patched.
 * Does not need a disassembler; the trade-off is that direct calls
 * (GetProcAddress + call, or Nt* calls) are not intercepted. Standard
 * Win32 apps (Notepad) call these APIs through the IAT, so this is
 * sufficient for the target.
 */
#pragma once
#include <windows.h>

/* One hook: the imported function name, our replacement, and a slot that
 * receives the original address. `dll` is the exporting module name
 * (e.g. "kernel32.dll"). */
typedef struct _WW_IAT_HOOK {
    const char *dll;
    const char *func;
    void *replacement;
    void **original;    /* out: original address */
} WW_IAT_HOOK;

/* Patch the IAT of `module` for every entry in `hooks` (count `nhooks`).
 * Returns the number of entries patched. Skips our own module. */
int WwIatHookModule(HMODULE module, const WW_IAT_HOOK *hooks, int nhooks);

/* Tell the IAT helper which module is ours, so it is never patched. */
void WwIatSetOwnModule(HMODULE m);

/* Patch every module currently loaded in this process. */
int WwIatHookAllModules(const WW_IAT_HOOK *hooks, int nhooks);
