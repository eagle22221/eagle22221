"""Writes evasion_section.inc: 512 fixed pseudo-random bytes for the fixture's
high-entropy packer-style section. Committed, so the build needs no network."""
import pathlib, random
rng = random.Random(99)
out = pathlib.Path(__file__).with_name("evasion_section.inc")
out.write_text(",".join(str(rng.randrange(256)) for _ in range(512)) + "\n")
