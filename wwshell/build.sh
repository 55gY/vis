#!/bin/bash
# Build the WaterWall shell extension (x64 + x86) with zig cross-compile.
#   wwshell64.dll -- 64-bit Explorer
#   wwshell.dll   -- 32-bit / WoW64
# Pure Win32 + hand-written COM (no ATL). Links the engine's sbox.
# Usage: ./build.sh
set -e
cd "$(dirname "$0")"
ZIG="$HOME/workspace/tools/zig-x86_64-linux-0.15.2/zig"
$ZIG cc -target x86_64-windows-gnu -O2 -shared -D_WIN32_WINNT=0x0601 \
    -o wwshell64.dll wwshell.c ../wweng/sbox.c wwshell.rc wwshell.def \
    -lshell32 -lole32 -luser32 -ladvapi32
$ZIG cc -target x86-windows-gnu -O2 -shared -D_WIN32_WINNT=0x0601 \
    -o wwshell.dll wwshell.c ../wweng/sbox.c wwshell.rc wwshell.def \
    -lshell32 -lole32 -luser32 -ladvapi32
ls -l wwshell64.dll wwshell.dll
md5sum wwshell64.dll wwshell.dll
