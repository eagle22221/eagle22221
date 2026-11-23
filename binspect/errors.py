"""Exception hierarchy. Every error binspect raises on purpose derives from
BinspectError, so callers can catch one type."""


class BinspectError(Exception):
    """Base class for all binspect errors."""


class UnknownFormatError(BinspectError):
    """The input is neither an ELF nor a PE file."""


class ParseError(BinspectError):
    """The input claims to be a known format but is truncated or corrupt."""


class MissingDependencyError(BinspectError):
    """An optional dependency (Capstone) is needed for this operation."""


class UnsupportedError(BinspectError):
    """The operation is not available for this binary (e.g. unknown CPU)."""


class LocationError(BinspectError):
    """A symbol name or address given by the user could not be resolved."""
