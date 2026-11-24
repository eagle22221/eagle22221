# binspect, native C version.
#
#   make            build/binspect           (this machine)
#   make windows    build/binspect.exe       (64-bit Windows, MinGW-w64, static)
#   make asan       build/binspect-asan      (AddressSanitizer + UBSan, for tests)
#   make clean
#
# The disassembly commands (disasm, functions, xrefs) use the Capstone engine,
# compiled from source in third_party/ (put there by ./fetch_capstone.sh).
# Without it the build still works and those commands report "this build has
# no disassembler"; CAPSTONE=0 forces that.

CC       ?= cc
AR       ?= ar
MINGW    ?= x86_64-w64-mingw32-gcc
MINGW_AR ?= x86_64-w64-mingw32-ar
OPT      ?= -O2
WARN      = -std=c11 -Wall -Wextra -Werror
# -ffp-contract=off: entropy must round exactly like the Python version.
CFLAGS    = $(OPT) $(WARN) -ffp-contract=off
SANITIZE  = -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

BUILD     = build
CORE      = util hash model elf pe strings json views techniques render platform patch cli main
HEADERS   = $(wildcard src/*.h)

# --- Capstone (third-party) -----------------------------------------------------
CS_VERSION = 5.0.9
CS_DIR     = third_party/capstone-$(CS_VERSION)/src
CAPSTONE  ?= $(if $(wildcard $(CS_DIR)/cs.c),1,0)
# Only the CPUs binspect can analyse; AT&T syntax is never used.
CS_ARCHS   = X86 AArch64 ARM Mips PowerPC
CS_DEFINES = -DCAPSTONE_USE_SYS_DYN_MEM -DCAPSTONE_X86_ATT_DISABLE -DCAPSTONE_HAS_X86 \
             -DCAPSTONE_HAS_ARM64 -DCAPSTONE_HAS_ARM -DCAPSTONE_HAS_MIPS -DCAPSTONE_HAS_POWERPC
CS_INCLUDE = -I$(CS_DIR)/include -I$(CS_DIR)
# Third-party code: built with its own (quiet) flags, not with -Werror.
CS_CFLAGS  = -O2 -std=gnu99 -w $(CS_DEFINES) $(CS_INCLUDE)
CS_SOURCES = $(wildcard $(CS_DIR)/*.c) $(foreach arch,$(CS_ARCHS),$(wildcard $(CS_DIR)/arch/$(arch)/*.c))
cs_objects = $(patsubst $(CS_DIR)/%.c,$(BUILD)/$(1)/capstone-$(CS_VERSION)/%.o,$(CS_SOURCES))

ifeq ($(CAPSTONE),1)
SOURCES     = $(CORE) disasm analysis
CS_USE      = -isystem $(CS_DIR)/include -isystem $(CS_DIR)
cs_library  = $(BUILD)/$(1)/libcapstone.a
else
SOURCES     = $(CORE) analysis_stub
CS_USE      =
cs_library  =
endif

objects = $(SOURCES:%=$(BUILD)/$(1)/%.o)

.PHONY: all windows asan clean
all: $(BUILD)/binspect
windows: $(BUILD)/binspect.exe
asan: $(BUILD)/binspect-asan

$(BUILD)/binspect: $(call objects,native) $(call cs_library,native)
	$(CC) $(CFLAGS) -o $@ $^ -lm

$(BUILD)/binspect-asan: $(call objects,asan) $(call cs_library,asan)
	$(CC) $(CFLAGS) -O1 $(SANITIZE) -o $@ $^ -lm

$(BUILD)/binspect.exe: $(call objects,windows) $(call cs_library,windows)
	$(MINGW) $(CFLAGS) -static -s -o $@ $^

$(BUILD)/native/%.o: src/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CS_USE) -c -o $@ $<

$(BUILD)/asan/%.o: src/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -O1 $(SANITIZE) $(CS_USE) -c -o $@ $<

$(BUILD)/windows/%.o: src/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(MINGW) $(CFLAGS) $(CS_USE) -c -o $@ $<

# Capstone objects and one static library per target. The sanitizer build
# checks Capstone's memory accesses too (AddressSanitizer only: undefined-
# behaviour reports from third-party code are not ours to fix).
$(BUILD)/native/capstone-$(CS_VERSION)/%.o: $(CS_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CS_CFLAGS) -c -o $@ $<

$(BUILD)/asan/capstone-$(CS_VERSION)/%.o: $(CS_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CS_CFLAGS) -O1 -g -fsanitize=address -fno-omit-frame-pointer -c -o $@ $<

$(BUILD)/windows/capstone-$(CS_VERSION)/%.o: $(CS_DIR)/%.c
	@mkdir -p $(@D)
	$(MINGW) $(CS_CFLAGS) -c -o $@ $<

$(BUILD)/native/libcapstone.a: $(call cs_objects,native)
	rm -f $@ && $(AR) rcs $@ $^

$(BUILD)/asan/libcapstone.a: $(call cs_objects,asan)
	rm -f $@ && $(AR) rcs $@ $^

$(BUILD)/windows/libcapstone.a: $(call cs_objects,windows)
	rm -f $@ && $(MINGW_AR) rcs $@ $^

clean:
	rm -rf $(BUILD)
