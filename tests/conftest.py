from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "bin"


def fixture_path(name: str) -> Path:
    return FIXTURES / name


def fixture_bytes(name: str) -> bytes:
    return fixture_path(name).read_bytes()


@pytest.fixture(scope="session")
def load_fixture():
    """Load a committed fixture binary once per test session."""
    import vex

    cache = {}

    def _load(name: str):
        if name not in cache:
            cache[name] = vex.load(fixture_path(name))
        return cache[name]

    return _load
