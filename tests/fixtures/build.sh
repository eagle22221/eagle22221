#!/bin/sh
# Rebuilds the binary fixtures in tests/fixtures/bin from tests/fixtures/src.
# Needs gcc, clang, lld (ld.lld + lld-link), llvm-dlltool and strip.
# The built binaries are committed, so the test suite itself needs no compiler.
# Rebuilding with a different toolchain changes addresses; the literal values
# in the tests were read from the committed binaries with readelf/llvm-readobj.
set -eu
cd "$(dirname "$0")"
SRC=src
OUT=bin
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

# --- Linux / ELF -----------------------------------------------------------
gcc -O1 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro,-z,now -o "$OUT/hello_elf64" "$SRC/hello.c"
strip -o "$OUT/hello_elf64_stripped" "$OUT/hello_elf64"

# Non-PIE variant: _start loads main with "mov rdi, imm" instead of "lea".
gcc -O1 -no-pie -fno-stack-protector -Wl,-z,norelro -o "$TMP/hello_nopie" "$SRC/hello.c"
strip -o "$OUT/hello_elf64_nopie_stripped" "$TMP/hello_nopie"

gcc -O1 -shared -fPIC -Wl,-soname,libsample.so.1 \
    -o "$OUT/libsample.so" "$SRC/libsample.c"

clang --target=i386-linux-gnu -O1 -nostdlib -static -ffreestanding -fno-pic \
    -fno-stack-protector -fuse-ld=lld -Wl,-z,execstack,--build-id=none \
    -o "$OUT/bare_elf32" "$SRC/bare.c"

clang --target=aarch64-linux-gnu -O1 -nostdlib -static -ffreestanding \
    -fno-stack-protector -fuse-ld=lld -Wl,--build-id=none \
    -o "$OUT/bare_arm64" "$SRC/bare.c"

# --- Windows / PE ----------------------------------------------------------
llvm-dlltool -m i386:x86-64 -d "$SRC/kernel32_x64.def" -l "$TMP/kernel32_x64.lib"
llvm-dlltool -m i386 -k -d "$SRC/kernel32_x86.def" -l "$TMP/kernel32_x86.lib"

clang --target=x86_64-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector \
    -funwind-tables -c "$SRC/winhello.c" -o "$TMP/winhello64.obj"
lld-link /nologo /entry:entry /subsystem:console /nodefaultlib \
    /dynamicbase /nxcompat /highentropyva /timestamp:1700000000 \
    /debug:symtab /out:"$OUT/hello_pe64.exe" \
    "$TMP/winhello64.obj" "$TMP/kernel32_x64.lib"

clang --target=i686-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector \
    -c "$SRC/winhello.c" -o "$TMP/winhello32.obj"
lld-link /nologo /entry:entry /subsystem:console /nodefaultlib \
    /dynamicbase:no /nxcompat:no /fixed /safeseh:no /timestamp:1700000000 \
    /out:"$OUT/hello_pe32.exe" \
    "$TMP/winhello32.obj" "$TMP/kernel32_x86.lib"

clang --target=x86_64-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector \
    -c "$SRC/sample_dll.c" -o "$TMP/sample_dll.obj"
lld-link /nologo /dll /entry:DllMain /nodefaultlib /timestamp:1700000000 \
    /debug /pdb:"$TMP/sample.pdb" /pdbaltpath:C:\\build\\sample.pdb \
    /export:sample_add,@7 /export:sample_greet \
    /export:sample_sleep=KERNEL32.Sleep \
    /out:"$OUT/sample.dll" /implib:"$TMP/sample.lib" \
    "$TMP/sample_dll.obj"

llvm-dlltool -m i386:x86-64 -d "$SRC/ws2_32_x64.def" -l "$TMP/ws2_32.lib"
llvm-dlltool -m i386:x86-64 -d "$SRC/user32_x64.def" -l "$TMP/user32.lib"
clang --target=x86_64-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector \
    -c "$SRC/netprobe.c" -o "$TMP/netprobe.obj"
lld-link /nologo /entry:entry /subsystem:console /nodefaultlib \
    /timestamp:1700000000 /delayload:USER32.dll /out:"$OUT/netprobe.exe" \
    "$TMP/netprobe.obj" "$TMP/kernel32_x64.lib" "$TMP/ws2_32.lib" "$TMP/user32.lib"

ls -l "$OUT"

# --- Technique-detection fixtures (anti-debug, injection, hooking, anti-VM) ----
python3 "$SRC/make_evasion_section.py" 2>/dev/null || true
llvm-dlltool -m i386:x86-64 -d "$SRC/evasion_k32.def"    -l "$TMP/ev_k32.lib"
llvm-dlltool -m i386:x86-64 -d "$SRC/evasion_ntdll.def"  -l "$TMP/ev_ntdll.lib"
llvm-dlltool -m i386:x86-64 -d "$SRC/evasion_user32.def" -l "$TMP/ev_user32.lib"
clang --target=x86_64-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector \
    -c "$SRC/evasion.c" -o "$TMP/evasion.obj" -I "$SRC"
lld-link /nologo /entry:entry /subsystem:console /nodefaultlib /timestamp:1700000000 \
    /section:UPX1,ER /out:"$OUT/evasion_pe64.exe" \
    "$TMP/evasion.obj" "$TMP/ev_k32.lib" "$TMP/ev_ntdll.lib" "$TMP/ev_user32.lib"
gcc -O1 -no-pie -fno-stack-protector -o "$TMP/evasion_elf64" "$SRC/evasion_linux.c"
strip -o "$OUT/evasion_elf64" "$TMP/evasion_elf64"
