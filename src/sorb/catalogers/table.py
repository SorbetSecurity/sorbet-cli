"""Table-driven lockfile catalogers (~70% of ecosystems are
declarative). One `LockfileSpec` yields a working cataloger with evidence
spans; a new format is a ~20-line contribution plus a fixture.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

import yaml

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    snippet_at,
)
from sorb.errors import DetectorFailure
from sorb.ident import make_purl
from sorb.model import ComponentClaim, Finding, Tier
from sorb.source.base import Entry

JSON = "json"
YAML = "yaml"
TOML = "toml"


@dataclass(frozen=True)
class LockfileSpec:
    id: str  # "dart/pubspec-lock"
    match: str = ""  # basename glob
    #: Full-path glob, for formats identified by the directory they sit in
    #: rather than their own name — `conda-meta/numpy-1.26.4-py312.json` says
    #: nothing on its own. Exactly one of `match`/`match_glob` is set.
    match_glob: str = ""
    format: str = JSON  # json|yaml|toml
    packages_at: str = "$"  # mini-path, e.g. "$.packages.*"; "$" = the file is one package
    fields: dict[str, str] = field(default_factory=dict)
    # field paths relative to each package node; "@key" = the mapping key
    purl_type: str = ""
    tier: Tier = Tier.LOCKED
    technique: str = "lockfile-parse"
    namespace_sep: str | None = None  # split name into namespace/name (composer)
    version_pkg: int = 1


def _load(fmt: str, blob: bytes) -> Any:
    text = blob.decode("utf-8", errors="replace")
    if fmt == JSON:
        return json.loads(text)
    if fmt == YAML:
        return yaml.safe_load(text)
    if fmt == TOML:
        return tomllib.loads(text)
    raise DetectorFailure(f"unknown table format {fmt!r}")


def _walk_path(doc: Any, path: str) -> Iterator[tuple[str | None, Any]]:
    """Evaluate the mini-path: '$' root, '.name' key access, '.*' dict values
    (yielding keys), '[*]' list items."""
    parts = path.replace("[*]", ".[*]").split(".")
    nodes: list[tuple[str | None, Any]] = [(None, doc)]
    for part in parts:
        if part in ("$", ""):
            continue
        nxt: list[tuple[str | None, Any]] = []
        for _key, node in nodes:
            if part == "*":
                if isinstance(node, dict):
                    nxt.extend((str(k), v) for k, v in node.items())
            elif part == "[*]":
                if isinstance(node, list):
                    # preserve the parent mapping key so "@key" still works
                    # after array-of-tables expansion (Julia Manifest.toml)
                    nxt.extend((_key, item) for item in node)
            else:
                if isinstance(node, dict) and part in node:
                    nxt.append((part, node[part]))
        nodes = nxt
    yield from nodes


def _get_field(key: str | None, node: Any, path: str) -> str | None:
    if path == "@key":
        return key
    if path == "@value":
        # A `name: version` mapping, where the whole value is the field. Common
        # enough (Unity packages, Perl prereqs) to be worth naming.
        return str(node) if isinstance(node, str | int | float) else None
    cur = node
    for part in path.lstrip("$.").split("."):
        if not part:
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    if cur is None:
        return None
    return str(cur)


class TableCataloger(Cataloger):
    def __init__(self, spec: LockfileSpec):
        if bool(spec.match) == bool(spec.match_glob):
            raise ValueError(f"{spec.id}: set exactly one of match / match_glob")
        self.spec = spec
        self.id = spec.id
        self.version = spec.version_pkg
        self.matchers = [
            Matcher(glob=spec.match_glob) if spec.match_glob else Matcher(basename=spec.match)
        ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        spec = self.spec
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = _load(spec.format, blob)
        except (json.JSONDecodeError, yaml.YAMLError, tomllib.TOMLDecodeError) as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if doc is None:
            return
        for key, node in _walk_path(doc, spec.packages_at):
            name = _get_field(key, node, spec.fields.get("name", "@key"))
            version = _get_field(key, node, spec.fields.get("version", "$.version"))
            if not name or not version:
                continue
            digest = None
            if "digest" in spec.fields:
                digest = _get_field(key, node, spec.fields["digest"])
            namespace = None
            purl_name = name
            if spec.namespace_sep and spec.namespace_sep in name:
                namespace, purl_name = name.split(spec.namespace_sep, 1)
            hashes: tuple[tuple[str, str], ...] = ()
            if digest:
                algo, _, hexval = digest.partition(":")
                if hexval:
                    hashes = ((algo, hexval),)
                else:
                    hashes = (("sha256", digest),)
            claim = ComponentClaim(
                ctype="library",
                name=name,
                version=version,
                purl=make_purl(spec.purl_type, purl_name, version, namespace=namespace),
                ecosystem=spec.purl_type,
                namespace=namespace,
                hashes=hashes,
            )
            ev = ctx.evidence(
                spec.technique,
                spec.tier,
                entry,
                span=find_span(text, name),
                captured=snippet_at(text, name, context=1),
            )
            yield Finding(claim=claim, evidence=(ev,))
