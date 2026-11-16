#!/usr/bin/env bash
# Rebuild the committed Windows SFX stub (tbfdesk-sfx-stub.exe) from source.
# Reproducible: run this whenever tbfdesk-sfx-stub.c / stub.manifest change, then commit
# the regenerated tbfdesk-sfx-stub.exe. The server include_bytes!s that committed binary;
# it never cross-compiles at build time (so the shipped bytes do not depend on the build
# host). Needs the MinGW-w64 toolchain: x86_64-w64-mingw32-gcc + -windres.
set -euo pipefail
cd "$(dirname "$0")"

CC=${CC:-x86_64-w64-mingw32-gcc}
WINDRES=${WINDRES:-x86_64-w64-mingw32-windres}
command -v "$CC" >/dev/null || { echo "missing $CC (install mingw-w64)"; exit 1; }
command -v "$WINDRES" >/dev/null || { echo "missing $WINDRES"; exit 1; }

"$WINDRES" stub.rc stub_rc.o
# -municode: wmain entry point. -mconsole: show progress + wait for Enter.
# -s: strip. -static-libgcc: no runtime DLL dependency on the target.
"$CC" -municode -O2 -s -static -static-libgcc \
    tbfdesk-sfx-stub.c stub_rc.o \
    -o tbfdesk-sfx-stub.exe \
    -mconsole -lkernel32 -luser32
rm -f stub_rc.o
echo "built tbfdesk-sfx-stub.exe ($(stat -c %s tbfdesk-sfx-stub.exe) bytes)"
file tbfdesk-sfx-stub.exe 2>/dev/null || true
