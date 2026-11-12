#!/bin/bash
# Build wwsvc.exe (x86_64 Windows) with zig cross-compile.
# Usage: ./build.sh
set -e
cd "$(dirname "$0")"
ZIG="$HOME/workspace/tools/zig-x86_64-linux-0.15.2/zig"
$ZIG cc -target x86_64-windows-gnu -O2 -Wno-macro-redefined -D_WIN32_WINNT=0x0601 \
    -o wwsvc.exe wwsvc.c wwdrv.c ripemd160.c inflate.c deflate_store.c xcf.c \
    policy_build.c wwflt_client.c wwinj_client.c
ls -l wwsvc.exe
md5sum wwsvc.exe
