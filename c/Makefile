# binspect, native C version.
#
#   make            build/binspect           (this machine)
#   make windows    build/binspect.exe       (64-bit Windows, MinGW-w64, static)
#   make asan       build/binspect-asan      (AddressSanitizer + UBSan, for tests)
#   make clean
#
# The disassembly commands need the Capstone engine (third_party/, fetched by
# ./fetch_capstone.sh). Without it the build still works and those commands
# report "this build has no disassembler"; force that with CAPSTONE=0.

CC      ?= cc
MINGW   ?= x86_64-w64-mingw32-gcc
OPT     ?= -O2
WARN     = -std=c11 -Wall -Wextra -Werror
# -ffp-contract=off: entropy must round exactly like the Python version.
CFLAGS   = $(OPT) $(WARN) -ffp-contract=off
ASAN     = -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

BUILD    = build
CORE     = util hash model elf pe strings json views render platform patch cli main
SOURCES  = $(CORE) analysis_stub
HEADERS  = $(wildcard src/*.h)

native_objects  = $(SOURCES:%=$(BUILD)/native/%.o)
asan_objects    = $(SOURCES:%=$(BUILD)/asan/%.o)
windows_objects = $(SOURCES:%=$(BUILD)/windows/%.o)

.PHONY: all windows asan clean
all: $(BUILD)/binspect
windows: $(BUILD)/binspect.exe
asan: $(BUILD)/binspect-asan

$(BUILD)/binspect: $(native_objects)
	$(CC) $(CFLAGS) -o $@ $^ -lm

$(BUILD)/binspect-asan: $(asan_objects)
	$(CC) $(CFLAGS) $(ASAN) -o $@ $^ -lm

$(BUILD)/binspect.exe: $(windows_objects)
	$(MINGW) $(CFLAGS) -static -s -o $@ $^

$(BUILD)/native/%.o: src/%.c $(HEADERS) | $(BUILD)/native
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/asan/%.o: src/%.c $(HEADERS) | $(BUILD)/asan
	$(CC) $(CFLAGS) $(ASAN) -c -o $@ $<

$(BUILD)/windows/%.o: src/%.c $(HEADERS) | $(BUILD)/windows
	$(MINGW) $(CFLAGS) -c -o $@ $<

$(BUILD)/native $(BUILD)/asan $(BUILD)/windows:
	mkdir -p $@

clean:
	rm -rf $(BUILD)
