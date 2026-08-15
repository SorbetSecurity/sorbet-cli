"""node-semver version + range algebra.

A faithful re-implementation of the parts npm resolution depends on:
version comparison (incl. prerelease ordering), comparator desugaring
(``^``, ``~``, x-ranges, partials, hyphen ranges), ``||`` alternatives, and
the prerelease-opt-in rule. Validated against recorded node-semver behavior
in the conformance fixtures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_VERSION_RE = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z\-.]+))?(?:\+[0-9A-Za-z\-.]+)?$"
)
_PARTIAL_RE = re.compile(
    r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z\-.]+))?(?:\+[0-9A-Za-z\-.]+)?$"
)


@total_ordering
@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @classmethod
    def parse(cls, s: str) -> Version:
        m = _VERSION_RE.match(s.strip())
        if not m:
            raise ValueError(f"invalid semver version: {s!r}")
        pre = tuple(m.group(4).split(".")) if m.group(4) else ()
        return cls(int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)

    @property
    def triple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{'.'.join(self.prerelease)}" if self.prerelease else base

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self.triple == other.triple and self.prerelease == other.prerelease

    def __lt__(self, other: Version) -> bool:
        if self.triple != other.triple:
            return self.triple < other.triple
        # no prerelease > any prerelease
        if not self.prerelease:
            return False
        if not other.prerelease:
            return True
        for a, b in zip(self.prerelease, other.prerelease, strict=False):
            if a == b:
                continue
            a_num, b_num = a.isdigit(), b.isdigit()
            if a_num and b_num:
                return int(a) < int(b)
            if a_num != b_num:
                return a_num  # numeric identifiers sort before alphanumeric
            return a < b
        return len(self.prerelease) < len(other.prerelease)

    def __hash__(self) -> int:
        return hash((self.triple, self.prerelease))


@dataclass(frozen=True)
class Comparator:
    op: str  # "<" | "<=" | ">" | ">=" | "="
    version: Version

    def satisfied_by(self, v: Version) -> bool:
        if self.op == "=":
            return v == self.version
        if self.op == "<":
            return v < self.version
        if self.op == "<=":
            return v <= self.version
        if self.op == ">":
            return v > self.version
        return v >= self.version


_ZERO_PRE = ("0",)  # the "-0" sentinel used by desugared upper bounds


def _lower_zero(major: int, minor: int = 0, patch: int = 0) -> Comparator:
    return Comparator(">=", Version(major, minor, patch))


def _upper_excl(major: int, minor: int = 0, patch: int = 0) -> Comparator:
    return Comparator("<", Version(major, minor, patch, _ZERO_PRE))


def _desugar(token: str) -> list[Comparator]:
    """One comparator token → primitive comparators (node-semver rules)."""
    token = token.strip()
    if token in ("", "*", "x", "X"):
        return [Comparator(">=", Version(0, 0, 0))]

    op = ""
    for candidate in (">=", "<=", ">", "<", "=", "^", "~"):
        if token.startswith(candidate):
            op = candidate
            token = token[len(candidate) :].strip()
            break
    m = _PARTIAL_RE.match(token)
    if not m:
        raise ValueError(f"invalid semver comparator: {op}{token!r}")
    parts = [m.group(1), m.group(2), m.group(3)]
    pre = tuple(m.group(4).split(".")) if m.group(4) else ()

    def is_x(p: str | None) -> bool:
        return p is None or p in ("x", "X", "*")

    maj_x, min_x, pat_x = is_x(parts[0]), is_x(parts[1]), is_x(parts[2])
    major = 0 if maj_x else int(parts[0] or 0)
    minor = 0 if min_x else int(parts[1] or 0)
    patch = 0 if pat_x else int(parts[2] or 0)
    v = Version(major, minor, patch, pre)

    if op == "^":
        if maj_x:
            return [Comparator(">=", Version(0, 0, 0))]
        if major > 0:
            return [Comparator(">=", v), _upper_excl(major + 1)]
        if min_x:
            return [_lower_zero(0), _upper_excl(1)]
        if minor > 0 or pat_x:
            return [Comparator(">=", v), _upper_excl(0, minor + 1)]
        return [Comparator(">=", v), _upper_excl(0, minor, patch + 1)]
    if op == "~":
        if maj_x:
            return [Comparator(">=", Version(0, 0, 0))]
        if min_x:
            return [_lower_zero(major), _upper_excl(major + 1)]
        return [Comparator(">=", v), _upper_excl(major, minor + 1)]
    if op in ("", "="):
        if maj_x:
            return [Comparator(">=", Version(0, 0, 0))]
        if min_x:
            return [_lower_zero(major), _upper_excl(major + 1)]
        if pat_x:
            return [_lower_zero(major, minor), _upper_excl(major, minor + 1)]
        return [Comparator("=", v)]
    if op == ">=":
        if min_x:
            return [_lower_zero(major)]
        if pat_x:
            return [_lower_zero(major, minor)]
        return [Comparator(">=", v)]
    if op == "<=":
        if min_x:
            return [_upper_excl(major + 1)]
        if pat_x:
            return [_upper_excl(major, minor + 1)]
        return [Comparator("<=", v)]
    if op == ">":
        if min_x:
            return [Comparator(">=", Version(major + 1, 0, 0, _ZERO_PRE))]
        if pat_x:
            return [Comparator(">=", Version(major, minor + 1, 0, _ZERO_PRE))]
        return [Comparator(">", v)]
    # op == "<"
    if min_x:
        return [_upper_excl(major)]
    if pat_x:
        return [_upper_excl(major, minor)]
    return [Comparator("<", v)]


_HYPHEN_RE = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")


@dataclass(frozen=True)
class Range:
    """A `||`-separated list of comparator sets (each set is an AND)."""

    alternatives: tuple[tuple[Comparator, ...], ...]
    raw: str

    @classmethod
    def parse(cls, raw: str) -> Range:
        alternatives: list[tuple[Comparator, ...]] = []
        for alt in raw.split("||"):
            alt = alt.strip()
            hy = _HYPHEN_RE.match(alt)
            comparators: list[Comparator] = []
            if hy:
                comparators.extend(_desugar(f">={hy.group(1)}"))
                comparators.extend(_desugar(f"<={hy.group(2)}"))
            else:
                # normalize "> 1.2.3" → ">1.2.3" before whitespace-splitting
                alt_norm = re.sub(r"(>=|<=|>|<|=|\^|~)\s+", r"\1", alt)
                tokens = alt_norm.split() if alt_norm else [""]
                for token in tokens:
                    comparators.extend(_desugar(token))
            alternatives.append(tuple(comparators))
        return cls(alternatives=tuple(alternatives), raw=raw)

    def satisfies(self, version: Version | str) -> bool:
        v = Version.parse(version) if isinstance(version, str) else version
        for comparators in self.alternatives:
            if all(c.satisfied_by(v) for c in comparators):
                if v.prerelease and v.prerelease != _ZERO_PRE:
                    # prerelease opt-in: some comparator in this set must carry
                    # a prerelease on the same [major, minor, patch] tuple
                    if not any(
                        c.version.prerelease and c.version.triple == v.triple
                        for c in comparators
                    ):
                        continue
                return True
        return False


def satisfies(version: str, range_: str) -> bool:
    try:
        return Range.parse(range_).satisfies(version)
    except ValueError:
        return False


def max_satisfying(versions: list[str], range_: str) -> str | None:
    """The highest version satisfying the range (npm's pick), or None."""
    try:
        r = Range.parse(range_)
    except ValueError:
        return None
    best: Version | None = None
    best_raw: str | None = None
    for raw in versions:
        try:
            v = Version.parse(raw)
        except ValueError:
            continue
        if r.satisfies(v) and (best is None or v > best):
            best, best_raw = v, raw
    return best_raw
