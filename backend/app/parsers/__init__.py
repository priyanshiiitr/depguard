"""
Deterministic manifest/lockfile parsers for ecosystems beyond npm.

Each parser module exposes:
    parse(text: str) -> tuple[list[ParsedDependency], list[SkippedEntry]]

Parsers never guess: anything without a concrete, pinned version is placed
in the skipped list with a reason instead of being emitted as a dependency.
"""
from dataclasses import dataclass


@dataclass
class ParsedDependency:
    name: str
    version: str
    ecosystem: str
    raw_line: str = ""


@dataclass
class SkippedEntry:
    raw: str
    reason: str


from . import requirements_txt, cargo_lock, go_sum, composer_lock, gemfile_lock  # noqa: E402

# filename (as it appears at the repo root) -> (parse function, OSV ecosystem string)
FILENAME_TO_PARSER = {
    "requirements.txt": (requirements_txt.parse, "PyPI"),
    "Cargo.lock": (cargo_lock.parse, "crates.io"),
    "go.sum": (go_sum.parse, "Go"),
    "composer.lock": (composer_lock.parse, "Packagist"),
    "Gemfile.lock": (gemfile_lock.parse, "RubyGems"),
}
