"""Windows registry-hive cataloger.

Matches offline `regf` hives (SOFTWARE / SYSTEM) surfaced by a `DiskImageSource`
and turns them into components: installed programs from the Uninstall keys, and
auto-start services from the SYSTEM control set. Evidence points at the exact
registry path. Uses the `sorb.host` regf reader (the sanctioned
catalogers→host seam).
"""

from __future__ import annotations

from collections.abc import Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.host.regf import Hive
from sorb.host.windows import auto_start_services, installed_programs
from sorb.model import ComponentClaim, EvidenceRecord, Finding, Tier
from sorb.source.base import Entry


class WindowsRegistryCataloger(Cataloger):
    id = "windows/registry"
    version = 1
    # hive files have no extension; match the regf magic plus the usual names.
    matchers = [
        Matcher(magic=b"regf"),
        Matcher(basename="SOFTWARE"),
        Matcher(basename="SYSTEM"),
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        if blob[:4] != b"regf":
            return
        try:
            hive = Hive(blob)
        except ValueError:
            return

        for prog in installed_programs(hive):
            yield Finding(
                claim=ComponentClaim(
                    ctype="application",
                    name=prog.name,
                    version=prog.version,
                    ecosystem="windows",
                    attrs=_attrs({"publisher": prog.publisher, "platform-source": "registry"}),
                ),
                evidence=(_ev(ctx, entry, prog.key_path,
                              f"{prog.name} {prog.version or ''}".strip(), Tier.INSTALLED),),
            )

        for svc in auto_start_services(hive):
            yield Finding(
                claim=ComponentClaim(
                    ctype="windows-service",
                    name=svc.name,
                    ecosystem="windows",
                    attrs=_attrs({
                        "display-name": svc.display_name,
                        "start": svc.start,
                        "image-path": svc.image_path,
                        "kind": "service",
                    }),
                ),
                # auto-start services are runtime-relevant → OBSERVED-adjacent, but
                # a hive is state-at-rest, so INSTALLED with a start=auto attr.
                evidence=(_ev(ctx, entry, svc.key_path,
                              f"service {svc.name} (start={svc.start})", Tier.INSTALLED),),
            )


def _attrs(d: dict[str, str | None]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((k, v) for k, v in d.items() if v))


def _ev(
    ctx: CatalogerContext, entry: Entry, key_path: str, captured: str, tier: Tier
) -> EvidenceRecord:
    ev = ctx.evidence("installed-state", tier, entry, captured=f"{key_path}: {captured}")
    # stamp the registry path onto the coordinates so `explain` shows it
    from dataclasses import replace

    return replace(ev, location=replace(ev.location, path=f"{entry.path}!{key_path}"))


register(WindowsRegistryCataloger())
