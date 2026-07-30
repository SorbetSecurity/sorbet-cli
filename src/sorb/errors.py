"""Error taxonomy.

Exit-code mapping lives here, in one place:

    0  success
    1  scan errors present (TargetError, or DetectorFailures recorded)
    2  policy failure (--fail-on matched)
    3  usage/config error (UsageError)
    4  internal error (InternalError — invariant broken)
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_SCAN_ERRORS = 1
EXIT_POLICY_FAIL = 2
EXIT_USAGE = 3
EXIT_INTERNAL = 4


class SorbError(Exception):
    """Base of the sorb error taxonomy."""

    exit_code: int = EXIT_INTERNAL


class UsageError(SorbError):
    """Bad flags/config → exit 3."""

    exit_code = EXIT_USAGE


class TargetError(SorbError):
    """Target unreachable/unreadable → abort scan, exit 1."""

    exit_code = EXIT_SCAN_ERRORS


class DetectorFailure(SorbError):
    """ONE file/detector failed (parse crash, timeout).

    Never propagated to abort a scan: caught, converted into a warning plus an
    `analysis-gap` annotation on the affected scope.
    """

    exit_code = EXIT_SCAN_ERRORS

    def __init__(self, message: str, *, path: str | None = None, detector: str | None = None):
        super().__init__(message)
        self.path = path
        self.detector = detector


class SubsystemDegraded(SorbError):
    """Cache down, enrichment unreachable, sandbox unavailable.

    Feature-level fallback + warning; the scan continues.
    """

    exit_code = EXIT_SCAN_ERRORS


class InternalError(SorbError):
    """Invariant broken → exit 4, plea to report."""

    exit_code = EXIT_INTERNAL


def exit_code_for(exc: BaseException) -> int:
    """Map any exception to its documented exit code (single source of truth)."""
    if isinstance(exc, SorbError):
        return exc.exit_code
    return EXIT_INTERNAL
