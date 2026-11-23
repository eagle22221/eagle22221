# binspect, native version

The same static reverse-engineering toolkit as the Python package in
`../binspect`, written in C so that it ships as one program with nothing to
install: `binspect.exe` on Windows, `binspect` on Linux. Files are never run;
originals are never changed unless you ask.

The Python version is the reference. For every command below, `--json`
output of the two is the same data (checked by `tests/test_c_port.py`).

## Build

    ./fetch_capstone.sh   # once: disassembler source into third_party/
    make                  # build/binspect        (this machine; gcc or clang)
    make windows          # build/binspect.exe    (64-bit Windows, needs MinGW-w64)
    make asan             # build/binspect-asan   (sanitizer build used by the tests)

`binspect.exe` is statically linked: copy the one file to any 64-bit Windows.
The code is C11 plus the compiler's 128-bit integer type (gcc, clang and
MinGW-w64 have it on 64-bit targets) and builds with `-Wall -Wextra -Werror`.

`disasm`, `functions` and `xrefs` use the [Capstone](https://www.capstone-engine.org)
engine 5.0.9 (BSD licence, see `third_party/capstone-5.0.9/src/LICENSE.TXT`),
compiled from source into the program. Without `third_party/` (or with
`make CAPSTONE=0`) everything else still builds and those commands answer
"this build has no disassembler".

## Use

    binspect [--json] [--color auto|always|never] COMMAND FILE [options]

    binspect report FILE                 everything at a glance
    binspect info FILE                   identity, hashes, security mitigations
    binspect sections | segments | imports | exports | layout FILE
    binspect symbols FILE [--grep TEXT]
    binspect strings FILE [-n MIN] [-e all|ascii|utf16] [--grep TEXT] [--tagged]
    binspect hexdump FILE [LOCATION] [--offset N] [-n BYTES]
    binspect functions FILE [--grep TEXT]
    binspect disasm FILE [LOCATION] [-n COUNT]
    binspect xrefs FILE TARGET | --string TEXT
    binspect patch bytes  FILE LOCATION HEX   [--offset] (-o OUT | --in-place)
    binspect patch nop    FILE LOCATION BYTES [--offset] (-o OUT | --in-place)
    binspect patch string FILE OLD NEW [-e ascii|utf16] (-o OUT | --in-place)

LOCATION and TARGET are a `0x` address, a function, symbol or import name
(optionally `library!name`), or `entry`. `binspect --help` lists everything.

On Windows you can also drop a file onto `binspect.exe`: that shows the
report and waits for Enter before the window closes.

## Differences from the Python version

* `--grep TEXT` is a plain, case-sensitive substring match, not a regular
  expression (there is no regex library to rely on under Windows).
* `segments` (ELF program headers) and `layout` (the file as consecutive
  regions) are extra commands; Python has these views but no command for them.
* A file given without a command is shown as a report instead of being a
  usage error, and `--json` / `--color` are accepted after the command too.
* Commands of the Python version that are not in `binspect --help` answer
  "only available in the Python version".
* Where Python stops with a traceback the C program does not: a `--offset`
  value that is not a number is an ordinary error, and `strings -n` with an
  absurdly large number simply finds nothing.
* Import hashes and `library!name` lookups fold only ASCII letters to lower
  case (names in real import tables are ASCII).
* On Windows a patched copy does not inherit a read-only attribute.

## Tests

    python3 -m pytest tests/test_c_port.py      # from the repository root

runs both implementations on every fixture, on system binaries, on programs
cross-compiled for other CPUs and byte orders (when clang/lld are installed)
and on thousands of deliberately corrupted files, the latter with the
sanitizer build. `BINSPECT_TEST_SANITIZED=1` runs everything with it.

## Layout of the source

    src/common.h util.c      memory arena, strings, errors, big integers
    src/model.[ch]           the parsed binary; bounds-checked reader
    src/elf.c  src/pe.c      the two parsers
    src/strings.[ch]         string extraction and tagging
    src/hash.[ch]            MD5, SHA-1, SHA-256
    src/views.[ch] json.[ch] the data of each command, as a JSON tree
    src/render.[ch]          the text form of each view
    src/disasm.[ch]          Capstone wrapper, operand analysis, names
    src/analysis.[ch]        function discovery, name resolution, xrefs
    src/patch.c              the patch commands
    src/cli.[ch] main.c      command line
    src/platform.[ch]        everything that differs between Windows and POSIX
