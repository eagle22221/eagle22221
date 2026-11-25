# vex, native C version.
#
#   make            build/vex           (this machine)
#   make windows    build/vex.exe       (64-bit Windows, MinGW-w64, static: the
#                   build/vex-app.exe    command-line program, the windowed one
#                   build/WebView2Loader.dll   and, with the SDK, its loader)
#   make asan       build/vex-asan      (AddressSanitizer + UBSan, for tests)
#   make probe      build/appwin-probe.exe (the native window on its own, for
#                                        checking it on a Windows PC)
#   make clean
#
# The disassembly commands (disasm, functions, xrefs) use the Capstone engine,
# compiled from source in third_party/ (put there by ./fetch_capstone.sh).
# Without it the build still works and those commands report "this build has
# no disassembler"; CAPSTONE=0 forces that.
#
# The native window of the Windows programs uses Microsoft Edge WebView2,
# through the SDK in third_party/webview2/ (put there by ./fetch_webview2.sh).
# Without it both programs are still built, with no native window: they show
# the interface in an app window instead. WEBVIEW2=0 forces that.

CC       ?= cc
AR       ?= ar
MINGW    ?= x86_64-w64-mingw32-gcc
MINGW_AR ?= x86_64-w64-mingw32-ar
MINGW_RC ?= x86_64-w64-mingw32-windres
PYTHON   ?= python3
OPT      ?= -O2
WARN      = -std=c11 -Wall -Wextra -Werror
# -ffp-contract=off: entropy must round exactly like the Python version.
CFLAGS    = $(OPT) $(WARN) -ffp-contract=off
SANITIZE  = -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

BUILD     = build
CORE      = util hash model elf pe strings json views techniques render platform fswalk split patch \
            pystr inflate aes decode cli main server window appwin
HEADERS   = $(wildcard src/*.h)
# The server runs on a thread of its own (vex gui).
THREADS   = -pthread

# --- web interface (vex gui) -----------------------------------------------
# tools/embed_web.py compiles vex/web into a C source served from memory.
WEB_DIR    = ../vex/web
WEB_FILES  = $(shell find $(WEB_DIR) -type f 2>/dev/null)
GEN_SRC    = $(BUILD)/gen/web_assets.c
web_object = $(BUILD)/$(1)/web_assets.o

# Asset packs and game-engine detection: the real implementation when both
# parts are present, otherwise the stub that reports the feature unavailable.
ifneq ($(and $(wildcard src/archives.c),$(wildcard src/engines.c)),)
ARCHIVES = archives engines
else
ARCHIVES = archives_stub
endif

# --- Capstone (third-party) -----------------------------------------------------
CS_VERSION = 5.0.9
CS_DIR     = third_party/capstone-$(CS_VERSION)/src
CAPSTONE  ?= $(if $(wildcard $(CS_DIR)/cs.c),1,0)
# Only the CPUs vex can analyse; AT&T syntax is never used.
CS_ARCHS   = X86 AArch64 ARM Mips PowerPC
CS_DEFINES = -DCAPSTONE_USE_SYS_DYN_MEM -DCAPSTONE_X86_ATT_DISABLE -DCAPSTONE_HAS_X86 \
             -DCAPSTONE_HAS_ARM64 -DCAPSTONE_HAS_ARM -DCAPSTONE_HAS_MIPS -DCAPSTONE_HAS_POWERPC
CS_INCLUDE = -I$(CS_DIR)/include -I$(CS_DIR)
# Third-party code: built with its own (quiet) flags, not with -Werror.
CS_CFLAGS  = -O2 -std=gnu99 -w $(CS_DEFINES) $(CS_INCLUDE)
CS_SOURCES = $(wildcard $(CS_DIR)/*.c) $(foreach arch,$(CS_ARCHS),$(wildcard $(CS_DIR)/arch/$(arch)/*.c))
cs_objects = $(patsubst $(CS_DIR)/%.c,$(BUILD)/$(1)/capstone-$(CS_VERSION)/%.o,$(CS_SOURCES))

ifeq ($(CAPSTONE),1)
SOURCES     = $(CORE) $(ARCHIVES) disasm analysis
CS_USE      = -isystem $(CS_DIR)/include -isystem $(CS_DIR)
cs_library  = $(BUILD)/$(1)/libcapstone.a
else
SOURCES     = $(CORE) $(ARCHIVES) analysis_stub
CS_USE      =
cs_library  =
endif

objects = $(SOURCES:%=$(BUILD)/$(1)/%.o)
# vex-app.exe: the same program with its own entry point (src/app_main.c).
app_objects = $(patsubst %,$(BUILD)/$(1)/%.o,$(filter-out main,$(SOURCES)) app_main)

# --- the native window (Windows) -------------------------------------------------
WV2_DIR   = third_party/webview2
WEBVIEW2 ?= $(if $(wildcard $(WV2_DIR)/WebView2.h),1,0)
ifeq ($(WEBVIEW2),1)
WV2_FLAGS  = -I$(WV2_DIR)
WV2_HEADER = $(WV2_DIR)/WebView2.h
WV2_LOADER = $(BUILD)/WebView2Loader.dll
else
WV2_FLAGS  = -DVEX_NO_WEBVIEW2
WV2_HEADER =
WV2_LOADER =
endif
# Every one of them is part of Windows: ws2_32 the server's sockets, shell32
# opening a browser tab and the command line, ole32 (+ uuid, a static library)
# COM for WebView2, user32 and gdi32 the windows and message boxes, advapi32
# the registry (where the browser and the system theme are found).
WIN_LIBS  = -lws2_32 -lshell32 -lole32 -luuid -luser32 -lgdi32 -ladvapi32

.PHONY: all windows asan probe clean
all: $(BUILD)/vex
windows: $(BUILD)/vex.exe $(BUILD)/vex-app.exe $(WV2_LOADER)
asan: $(BUILD)/vex-asan
probe: $(BUILD)/appwin-probe.exe $(WV2_LOADER)

$(BUILD)/vex: $(call objects,native) $(call web_object,native) $(call cs_library,native)
	$(CC) $(CFLAGS) $(THREADS) -o $@ $^ -lm

$(BUILD)/vex-asan: $(call objects,asan) $(call web_object,asan) $(call cs_library,asan)
	$(CC) $(CFLAGS) -O1 $(SANITIZE) $(THREADS) -o $@ $^ -lm

$(BUILD)/vex.exe: $(call objects,windows) $(call web_object,windows) $(BUILD)/windows/vex_res.o $(call cs_library,windows)
	$(MINGW) $(CFLAGS) -static -s -o $@ $^ $(WIN_LIBS)

# -mwindows: a windowed program, which never opens a console window.
$(BUILD)/vex-app.exe: $(call app_objects,windows) $(call web_object,windows) $(BUILD)/windows/vex_app_res.o $(call cs_library,windows)
	$(MINGW) $(CFLAGS) -static -s -mwindows -o $@ $^ $(WIN_LIBS)

$(BUILD)/appwin-probe.exe: tools/appwin_probe.c $(BUILD)/windows/appwin.o $(BUILD)/windows/window.o
	$(MINGW) $(CFLAGS) -static -s -mwindows -o $@ $^ $(WIN_LIBS)

$(BUILD)/WebView2Loader.dll: $(WV2_DIR)/WebView2Loader.dll
	cp $< $@

# The icon and the version details shown by Windows Explorer.
$(BUILD)/windows/vex_res.o: res/vex.rc res/vex.ico
	@mkdir -p $(dir $@)
	$(MINGW_RC) -O coff -o $@ res/vex.rc

$(BUILD)/windows/vex_app_res.o: res/vex.rc res/vex.ico
	@mkdir -p $(dir $@)
	$(MINGW_RC) -DVEX_APP -O coff -o $@ res/vex.rc

$(BUILD)/native/%.o: src/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(THREADS) $(CS_USE) -c -o $@ $<

$(BUILD)/asan/%.o: src/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -O1 $(SANITIZE) $(THREADS) $(CS_USE) -c -o $@ $<

$(BUILD)/windows/%.o: src/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(MINGW) $(CFLAGS) $(CS_USE) -c -o $@ $<

# The native window: built against the WebView2 SDK when it is there.
$(BUILD)/windows/appwin.o: src/appwin.c $(HEADERS) $(WV2_HEADER)
	@mkdir -p $(@D)
	$(MINGW) $(CFLAGS) $(WV2_FLAGS) -c -o $@ $<

# The embedded web interface: generated from vex/web, then compiled like
# any other source (-Isrc so the generated file finds server.h).
$(GEN_SRC): tools/embed_web.py $(WEB_FILES)
	@mkdir -p $(@D)
	$(PYTHON) $< $(WEB_DIR) $@

$(BUILD)/native/web_assets.o: $(GEN_SRC) $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

$(BUILD)/asan/web_assets.o: $(GEN_SRC) $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -O1 $(SANITIZE) -Isrc -c -o $@ $<

$(BUILD)/windows/web_assets.o: $(GEN_SRC) $(HEADERS)
	@mkdir -p $(@D)
	$(MINGW) $(CFLAGS) -Isrc -c -o $@ $<

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
