#!/bin/bash
# Build wweng64.dll (x86_64 Windows) with zig cross-compile.
# Usage: ./build.sh
# Hooks file APIs with Microsoft Detours (vendored in detours/),
# the same mechanism the vendor engine (wwkrn64.dll) uses.
set -e
cd "$(dirname "$0")"
ZIG="$HOME/workspace/tools/zig-x86_64-linux-0.15.2/zig"
$ZIG c++ -target x86_64-windows-gnu -O2 -shared -Wno-macro-redefined -D_WIN32_WINNT=0x0601 \
    -o wweng64.dll wweng.c policy.c sbox.c xcf.c inflate.c deflate_store.c policy_build.c \
    detours/detours.cpp detours/disasm.cpp detours/disolx64.cpp detours/image.cpp detours/modules.cpp \
    -lpsapi -ladvapi32
ls -l wweng64.dll
md5sum wweng64.dll
