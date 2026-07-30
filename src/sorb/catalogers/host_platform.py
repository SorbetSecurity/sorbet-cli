"""Host platform components: kernel + loaded modules.

A live-host scan surfaces the kernel itself and its loaded modules as *platform*
components, from the virtual files a `LiveHostSource` yields (`proc/version`,
`proc/modules`). Loaded modules are code that is running *right now*, so they
land at OBSERVED tier — the same honesty rule as runtime augmentation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.ident import make_purl
from sorb.model import ComponentClaim, EdgeClaim, EdgeType, Finding, Tier
from sorb.source.base import Entry

_KERNEL_RE = re.compile(r"Linux version (\S+)")


class KernelCataloger(Cataloger):
    id = "host/kernel"
    version = 1
    matchers = [Matcher(glob="*proc/version")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        m = _KERNEL_RE.search(text)
        if not m:
            return
        release = m.group(1)
        version = release.split("-", 1)[0]
        purl = make_purl("generic", "linux-kernel", version, qualifiers={"release": release})
        yield Finding(
            claim=ComponentClaim(
                ctype="operating-system",
                name="linux-kernel",
                version=release,
                purl=purl,
                ecosystem="generic",
                attrs=(("platform", "true"), ("kind", "kernel")),
            ),
            evidence=(
                ctx.evidence(
                    "installed-state", Tier.OBSERVED, entry, span=(1, 1),
                    captured=text.strip()[:120],
                ),
            ),
        )


class KernelModulesCataloger(Cataloger):
    id = "host/kernel-modules"
    version = 1
    matchers = [Matcher(glob="*proc/modules")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            parts = line.split()
            if len(parts) < 4:
                continue
            name, size = parts[0], parts[1]
            state = parts[4] if len(parts) >= 5 else ""
            attrs = [("platform", "true"), ("kind", "kernel-module")]
            if size.isdigit():
                attrs.append(("size", size))
            if state:
                attrs.append(("module-state", state))
            yield Finding(
                claim=ComponentClaim(
                    ctype="kernel-module",
                    name=name,
                    ecosystem="kernel",
                    attrs=tuple(attrs),
                ),
                evidence=(
                    ctx.evidence(
                        "installed-state", Tier.OBSERVED, entry, span=(lineno, lineno),
                        captured=line[:80],
                    ),
                ),
                edges=(
                    EdgeClaim(
                        kind=EdgeType.RUNS,
                        src="source:s1",
                        dst=f"claim:kernel/{name}@",
                    ),
                ),
            )


register(KernelCataloger())
register(KernelModulesCataloger())
