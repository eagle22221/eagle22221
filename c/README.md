# vex, native version

The same static reverse-engineering toolkit as the Python package in
`../vex`, written in C so that it ships as one program with nothing to
install: `vex.exe` on Windows, `vex` on Linux. Files are never run;
originals are never changed unless you ask.

The Python version is the reference. For every command below, `--json`
output of the two is the same data (checked by `tests/test_c_port.py`).

## Build

    ./fetch_capstone.sh   # once: disassembler source into third_party/
    make                  # build/vex        (this machine; gcc or clang)
    make windows          # build/vex.exe    (64-bit Windows, needs MinGW-w64)
    make asan             # build/vex-asan   (sanitizer build used by the tests)

`vex.exe` is statically linked: copy the one file to any 64-bit Windows.
The code is C11 plus the compiler's 128-bit integer type (gcc, clang and
MinGW-w64 have it on 64-bit targets) and builds with `-Wall -Wextra -Werror`.

`disasm`, `functions` and `xrefs` use the [Capstone](https://www.capstone-engine.org)
engine 5.0.9 (BSD licence, see `third_party/capstone-5.0.9/src/LICENSE.TXT`),
compiled from source into the program. Without `third_party/` (or with
`make CAPSTONE=0`) everything else still builds and those commands answer
"this build has no disassembler".

## Use

    vex [--json] [--color auto|always|never] COMMAND FILE [options]

    vex report FILE                 everything at a glance
    vex info FILE                   identity, hashes, security mitigations
    vex sections | segments | imports | exports | layout FILE
    vex symbols FILE [--grep TEXT]
    vex strings FILE [-n MIN] [-e all|ascii|utf16] [--grep TEXT] [--tagged]
    vex hexdump FILE [LOCATION] [--offset N] [-n BYTES]
    vex functions FILE [--grep TEXT]
    vex disasm FILE [LOCATION] [-n COUNT]
    vex xrefs FILE TARGET | --string TEXT
    vex split FILE FOLDER           save the parts of the file as separate files
    vex decode SOURCE [--recipe "op[:k=v,...][|op...]"] [--out FILE]
    vex decode SOURCE --solve NAME  caesar, xor-single, xor-keylen or substitution
    vex decode --list               the operations, and which of them this build has
    vex patch bytes  FILE LOCATION HEX   [--offset] (-o OUT | --in-place)
    vex patch nop    FILE LOCATION BYTES [--offset] (-o OUT | --in-place)
    vex patch string FILE OLD NEW [-e ascii|utf16] (-o OUT | --in-place)

LOCATION and TARGET are a `0x` address, a function, symbol or import name
(optionally `library!name`), or `entry`. `vex --help` lists everything.

On Windows you can also drop a file onto `vex.exe`: that shows the
report and waits for Enter before the window closes.

## Differences from the Python version

* `--grep TEXT` is a plain, case-sensitive substring match, not a regular
  expression (there is no regex library to rely on under Windows).
* `segments` (ELF program headers) and `layout` (the file as consecutive
  regions) are extra commands; Python has these views but no command for them.
* A file given without a command is shown as a report instead of being a
  usage error, and `--json` / `--color` are accepted after the command too.
* `split` saves the parts of the file and the files embedded in it, byte for
  byte as the Python version does, but not Windows resources (the `resources/`
  folder and its rows of `index.txt`): there is no resource reader here.
* `decode` gives the same results, messages and exit status as the Python
  version for everything it has, but it does not have everything; see below.
* Commands of the Python version that are not in `vex --help` answer
  "only available in the Python version".
* Where Python stops with a traceback the C program does not: a `--offset`
  value that is not a number is an ordinary error, and `strings -n` with an
  absurdly large number simply finds nothing.
* Import hashes and `library!name` lookups fold only ASCII letters to lower
  case (names in real import tables are ASCII).
* On Windows a patched copy does not inherit a read-only attribute.

## What `decode` does not decode here

`vex decode` is the decode and cipher workbench of the Python version (the
specification is `../docs/dev/decode-spec.md`): the same sources, recipe
grammar, result object, solvers, 64 MiB limit and HTTP routes, checked against
the Python version by `tests/test_c_decode.py`. Decompression looks at the
limit after every megabyte, so a decompression bomb is refused, not expanded.

Four operations, and one mode of a fifth, are left to the Python version:

| Operation | Here |
| --- | --- |
| `bunzip2`, `unxz` | not available (there is no bzip2 or xz decoder in the program) |
| `des`, `3des` | not available |
| `aes` with `mode=gcm` | not available; `ecb`, `cbc` and `ctr` are |

They are still listed (`vex decode --list` and `GET /api/decode/ops` mark them
`available: false`, which is how the graphical interface knows to grey them
out), a recipe may still name them, and using one fails that step with
`<name> is not available in this build` (`aes-gcm is not available in this
build` for the GCM mode), the words the Python version has for a primitive
its own build lacks. Everything else is here: every encoding, `raw-inflate`,
`zlib-inflate`, `gunzip`, every classic cipher, `xor`, `rc4`, `chacha20`,
`aes` (ECB, CBC, CTR; NIST FIPS-197 and SP 800-38A vectors are in the tests)
and `hash`.

Where the Python version stops with an internal error (a traceback, or HTTP
500 from the interface) the C program reports an ordinary failure instead:

* text that cannot be encoded (a `--text` argument that is not UTF-8, a
  `--base64` argument with a character above U+00FF, a lone surrogate in a
  JSON string): the result is `ok: false` with the codec's message;
* a Vigenere key with a letter whose upper case is two letters (`ß`), or a
  substitution map made of 26 letters that are not A to Z, used on text that
  has letters: the step fails with the message for a bad key or map;
* `railfence` with a number of rails in the millions or more: the Python
  version counts through every rail (for hours, or until memory runs out);
  here rails beyond the length of the data cost nothing;
* in a request to the HTTP API, `params` or `recipe` of the wrong JSON type
  (the step fails, or the request is refused with 400), a `path` that is not
  text (400), and JSON nested more than 512 levels deep (400; Python reads
  on to a depth of several thousand, then fails);
* an `--out` file that cannot be written is reported as `cannot write FILE:
  reason` (the Python version says `cannot read None`).

## Tests

    python3 -m pytest tests/test_c_port.py      # from the repository root
    python3 -m pytest tests/test_c_decode.py    # the decode workbench

The first runs both implementations on every fixture, on system binaries, on programs
cross-compiled for other CPUs and byte orders (when clang/lld are installed)
and on thousands of deliberately corrupted files, the latter with the
sanitizer build. `VEX_TEST_SANITIZED=1` runs everything with it.

## Layout of the source

    src/common.h util.c      memory arena, strings, errors, big integers
    src/model.[ch]           the parsed binary; bounds-checked reader
    src/elf.c  src/pe.c      the two parsers
    src/strings.[ch]         string extraction and tagging
    src/hash.[ch]            MD5, SHA-1, SHA-256
    src/decode.[ch]          the decode workbench: operations, recipes, solvers
    src/aes.[ch]             the AES block cipher (for decode)
    src/inflate.[ch]         DEFLATE decoder and CRC-32 (asset packs, decode)
    src/pystr.[ch]           Python's text rules: repr(), int(), str.upper(), ...
    src/unicode_data.h       character tables for pystr.c (tools/gen_unicode.py)
    src/views.[ch] json.[ch] the data of each command, as a JSON tree
    src/render.[ch]          the text form of each view
    src/disasm.[ch]          Capstone wrapper, operand analysis, names
    src/analysis.[ch]        function discovery, name resolution, xrefs
    src/patch.c              the patch commands
    src/cli.[ch] main.c      command line
    src/platform.[ch]        everything that differs between Windows and POSIX
