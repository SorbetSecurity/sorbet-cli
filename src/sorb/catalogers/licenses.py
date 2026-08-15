"""LICENSE-file cataloger.

Detects the license of LICENSE/COPYING files by normalized-token matching and
records the verdict as a ``license-detected`` annotation on the containing
project. When a sibling manifest *declares* a different license, that is a
``license-mismatch`` annotation — declared and detected stay separate,
disagreement is surfaced.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Iterable

from sorb.cache import default_cache_dir
from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import dirname_of, ref_project
from sorb.ident.licenses import detect_license
from sorb.model import Annotation, ComponentClaim, Finding, Tier
from sorb.source.base import Entry


def _declared_license_nearby(ctx: CatalogerContext, proj_dir: str) -> tuple[str, str] | None:
    """(license, manifest path) declared by a sibling manifest, if any."""
    prefix = "" if proj_dir == "." else f"{proj_dir}/"
    pkg = ctx.peek(f"{prefix}package.json")
    if pkg is not None:
        try:
            license_ = json.loads(pkg).get("license")
            if isinstance(license_, str) and license_:
                return license_, f"{prefix}package.json"
        except (json.JSONDecodeError, AttributeError):
            pass
    pyproject = ctx.peek(f"{prefix}pyproject.toml")
    if pyproject is not None:
        try:
            project = tomllib.loads(pyproject.decode("utf-8", "replace")).get("project") or {}
            license_ = project.get("license")
            if isinstance(license_, dict):
                license_ = license_.get("text")
            if isinstance(license_, str) and license_:
                return license_, f"{prefix}pyproject.toml"
        except tomllib.TOMLDecodeError:
            pass
    composer = ctx.peek(f"{prefix}composer.json")
    if composer is not None:
        try:
            license_ = json.loads(composer).get("license")
            if isinstance(license_, list):
                license_ = " OR ".join(str(x) for x in license_)
            if isinstance(license_, str) and license_:
                return license_, f"{prefix}composer.json"
        except (json.JSONDecodeError, AttributeError):
            pass
    return None


class LicenseFileCataloger(Cataloger):
    id = "license/file"
    version = 1
    matchers = [
        Matcher(basename="LICENSE"),
        Matcher(basename="LICENSE.*"),
        Matcher(basename="LICENCE"),
        Matcher(basename="COPYING"),
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        if "node_modules/" in entry.path or "site-packages/" in entry.path:
            return  # dependency licenses ride on their own components
        text = blob.decode("utf-8", errors="replace")
        match = detect_license(text, packs_dir=default_cache_dir() / "packs")
        proj_dir = dirname_of(entry.path)
        subject = ref_project(proj_dir)
        annotations: list[Annotation] = []
        if match is None:
            annotations.append(
                Annotation(
                    code="license-undetected",
                    subject=subject,
                    detail=f"{entry.path}: no corpus entry matched ≥ threshold "
                    "(seed corpus; `sorb db update` fetches the full one)",
                )
            )
        else:
            annotations.append(
                Annotation(
                    code="license-detected",
                    subject=subject,
                    detail=f"{entry.path}: {match.spdx_id} "
                    f"(score {match.score}, matched {match.corpus_entry})",
                    attrs=(("spdx", match.spdx_id), ("score", str(match.score)), ("path", entry.path)),
                )
            )
            declared = _declared_license_nearby(ctx, proj_dir)
            if declared is not None and declared[0].strip() != match.spdx_id:
                annotations.append(
                    Annotation(
                        code="license-mismatch",
                        subject=subject,
                        detail=f"{declared[1]} declares {declared[0]!r} but {entry.path} "
                        f"is {match.spdx_id} (score {match.score})",
                    )
                )
        yield Finding(
            claim=ComponentClaim(ctype="edge-only", name=f"license:{entry.path}"),
            evidence=(
                ctx.evidence(
                    "license-file",
                    Tier.DECLARED,
                    entry,
                    captured=text.splitlines()[0][:120] if text.splitlines() else None,
                ),
            ),
            annotations=tuple(annotations),
        )


register(LicenseFileCataloger())
