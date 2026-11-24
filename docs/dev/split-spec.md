# `vex split` — specification

Purpose: save the parts of a program (ELF or PE) as separate files in a folder.
It only copies bytes that are already in the file. No decryption, unpacking,
decompression or running of anything. The original is never modified.

## Command

    vex split FILE FOLDER          (also: vex --json split FILE FOLDER)

FOLDER is created if missing. If it exists it must be an empty directory,
otherwise fail with the message `FOLDER is not empty; choose a new or empty folder`
(FOLDER = the path as given) and write nothing.

## Pieces

Every piece is a dict: `path` (relative, forward slashes, or null when not saved),
`kind`, `name`, `offset` (file offset, int), `size` (int), `address`
(hex string like "0x140001000" from offset_to_vaddr, or null), `note` (string, may be "").

Pieces are listed in this order:

1. **Parts** — the regions of `views.layout(binary)["regions"]`, in order, numbered
   from 0 across all regions (padding included in the numbering).
   - kind = the region's kind (headers, code, data, meta, tables…, overlay, padding).
   - Non-padding regions are saved to `parts/NN_<safe>.bin`, NN = index as `%02d`,
     `<safe>` = region name with every character outside `[A-Za-z0-9._-]` replaced
     by `_` (empty name -> `unnamed`).
   - A padding region is saved (as `parts/NN_padding.bin`) only if it contains a
     non-zero byte; otherwise path is null and note is `zero padding, not saved`.
   - Property: concatenating all parts in order, with `size` zero bytes for each
     unsaved padding piece, reproduces the original file exactly.
2. **Embedded files** — complete files found inside the program, kind `embedded`.
   Scan file offsets 1 .. size-1 in increasing order (offset 0 is the program
   itself). On a hit of length L at offset o, record it and resume at o+L
   (hits never overlap). Recognised formats, each needing an exact computed length
   that fits inside the file:
   - `png`: 8-byte signature; walk chunks (length, type, data, crc); first chunk
     must be IHDR of length 13 with a correct CRC-32; ends after IEND.
   - `gif`: `GIF87a`/`GIF89a`; logical screen descriptor, optional global colour
     table, then blocks (0x2C image with optional local table + LZW min code byte +
     sub-blocks; 0x21 extension + label + sub-blocks) until trailer 0x3B. At least
     one image block required.
   - `wav`/`avi`/`webp`: `RIFF` + u32le size + form type `WAVE`/`AVI `/`WEBP`;
     length = size + 8; size >= 4.
   - `zip`: `PK\x03\x04` local header; find the first end-of-central-directory
     record (`PK\x05\x06`) after it for which `start + cd_offset + cd_size == eocd
     position` and cd_offset points at a `PK\x01\x02` signature; length runs to the
     end of the EOCD including its comment.
   - `exe` (PE): `MZ`, e_lfanew within the file, `PE\0\0`, sane section count
     (1..96); length = max(SizeOfHeaders, max raw pointer + raw size over sections);
     must be >= 512 bytes. Use ext `dll` when the DLL characteristic bit is set.
   - `elf`: `\x7fELF`, valid class (1/2) and data (1/2) and version 1; length =
     max(end of section header table, end of program header table, max
     offset+filesz over segments, max offset+size over non-NOBITS sections);
     must be >= 84 bytes.
   Saved as `embedded/NNN_0x<offset as 8 lowercase hex digits>.<ext>`, NNN = `%03d`
   counter from 0. name = `<ext> file`. note = `found inside <name of the part
   region containing the offset>`.
3. **Resources** (Python edition only, PE only) — every resource from
   `resources.list_resources`, kind `resource`, saved under `resources/` with the
   same file naming as `vex resources extract`. If a file has broken resources,
   skip this group and continue.

## Index

`index.txt` is written in FOLDER: a header line naming the source file, its size
and SHA-256, then one aligned row per piece (offset in hex, size, kind, path or
`-`, name, note). The exact layout is whatever the Python edition writes; the C
edition must match it byte for byte (for the pieces it produces).

## Result (JSON)

    {"dest": "<absolute folder>", "count": <files written, excluding index.txt>,
     "bytes": <total bytes written, excluding index.txt>, "index": "index.txt",
     "pieces": [ ...piece dicts... ]}

Human-readable CLI output: the piece table, then `Saved N files to FOLDER`.

## HTTP API (both servers)

- `GET  /api/split?path=P`          -> preview: same JSON with `dest` null,
  `count` and `bytes` = what would be written; nothing touches the disk.
- `POST /api/split?path=P&dest=D`   -> performs the split, returns the result.
  A non-empty folder is a 400 error with the message above.

## Clarifications (as implemented by the Python edition, which is the reference)

- Part file names: `<safe>` is cut to 64 characters.
- PNG: only the IHDR CRC is checked; the file ends after the first IEND chunk.
- RIFF: length is `size + 8`, with no even-padding adjustment.
- ZIP: an end record counts only if all 22 bytes and its comment fit in the file.
- PE: the 64-byte DOS header and `PE+88` bytes must be inside the file; the whole
  section table must be inside the file; all sections count; DLL bit is 0x2000.
- ELF: version means `e_ident[6] == 1`; program/section header entry sizes must be
  exactly 32/56 and 40/64 when the counts are non-zero; both byte orders.
- A destination that is an existing file is refused with the same "not empty" message.
- Resources: skipped as a whole if any cannot be read; name collisions get `_2`, `_3`…;
  a GROUP_ICON piece's size is the rebuilt `.ico` length.
- index.txt: line 1 is `<basename>: <size> bytes, SHA-256 <hex>`; rows are
  `0x%08x` offset, right-aligned size, kind, path or `-`, name, note, separated by
  two spaces; each group (parts, embedded, resources) is aligned on its own;
  characters outside 0x20–0x7E in names and notes are written as `?`.
