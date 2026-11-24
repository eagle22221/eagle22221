"""vex: static reverse-engineering toolkit for ELF and PE binaries."""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from .errors import (
    VexError,
    LocationError,
    MissingDependencyError,
    ParseError,
    UnknownFormatError,
    UnsupportedError,
)
from .model import Binary, Export, Import, Section, Segment, Symbol, entropy

__version__ = "0.1.0"

__all__ = [
    "Binary", "Section", "Segment", "Symbol", "Import", "Export",
    "VexError", "UnknownFormatError", "ParseError",
    "MissingDependencyError", "UnsupportedError", "LocationError",
    "load", "load_bytes", "entropy", "__version__",
]


def load_bytes(data: bytes, path: Optional[str] = None) -> Binary:
    """Parse an in-memory ELF or PE image. The file is never executed."""
    if data[:4] == b"\x7fELF":
        from . import elf
        return elf.parse(data, path)
    if data[:2] == b"MZ":
        from . import pe
        return pe.parse(data, path)
    raise UnknownFormatError(
        "not an ELF or PE file (no \\x7fELF or MZ signature)"
        if data else "file is empty"
    )


def load(path: Union[str, Path]) -> Binary:
    """Read and parse a binary from disk."""
    return load_bytes(Path(path).read_bytes(), str(path))
