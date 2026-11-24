"""Exception hierarchy. Every error vex raises on purpose derives from
VexError, so callers can catch one type."""


class VexError(Exception):
    """Base class for all vex errors."""


class UnknownFormatError(VexError):
    """The input is neither an ELF nor a PE file."""


class ParseError(VexError):
    """The input claims to be a known format but is truncated or corrupt."""


class MissingDependencyError(VexError):
    """An optional dependency (Capstone) is needed for this operation."""


class UnsupportedError(VexError):
    """The operation is not available for this binary (e.g. unknown CPU)."""


class LocationError(VexError):
    """A symbol name or address given by the user could not be resolved."""
