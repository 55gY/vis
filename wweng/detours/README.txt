Microsoft Detours 4.0.1 (https://github.com/microsoft/Detours), MIT licensed.
Vendored here because the vendor engine (wwkrn64.dll) hooks file APIs
with Detours (inline/trampoline patching of the function body), not IAT.
Only the files needed for DetourAttach on x64 are kept:
  detours.h/.cpp, disasm.cpp, disolx64.cpp, image.cpp, modules.cpp, detver.h.
Built with the same Zig cross-compile as wweng64.dll.
