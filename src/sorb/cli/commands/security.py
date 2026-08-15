"""Air-gapped signing and verification.

Commands are thin adapters: parse arguments, call into `sorb.core`,
render. Heavy imports stay inside command bodies so `sorb --help`
keeps its startup budget.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:

    pass

from sorb.cli.app import app
from sorb.errors import (
    EXIT_POLICY_FAIL,
    SorbError,
    UsageError,
    exit_code_for,
)


@app.command()
def sign(
    sbom: str = typer.Argument(..., help="SBOM file to sign"),
    key: str | None = typer.Option(None, "--key", help="Private key PEM (with --generate-key, where to write it)"),
    generate_key: bool = typer.Option(False, "--generate-key", help="Generate a keypair first"),
    out: str | None = typer.Option(None, "--out", help="Bundle path (default <sbom>.sig)"),
) -> None:
    """Detached signature bundle over the exact SBOM bytes."""
    from sorb.emit.signing import generate_keypair, sign_detached

    try:
        if generate_key:
            key_path, pub_path = generate_keypair(
                Path(key).parent if key else Path("."), stem=Path(key).stem if key else "sorb"
            )
            typer.echo(f"  keypair written: {key_path} / {pub_path}", err=True)
        elif key is None:
            raise UsageError("--key is required (or pass --generate-key)")
        else:
            key_path = Path(key)
        bundle = sign_detached(Path(sbom).read_bytes(), private_key_pem=key_path.read_bytes())
        dest = Path(out) if out else Path(sbom + ".sig")
        dest.write_bytes(bundle)
        typer.echo(f"  {dest} written (detached signature bundle)", err=True)
    except (SorbError, ValueError, OSError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e) if isinstance(e, SorbError) else 1) from e


@app.command()
def attest(
    sbom: str = typer.Argument(..., help="SBOM file to attest (CycloneDX/SPDX JSON)"),
    key: str = typer.Option(..., "--key", help="Private key PEM"),
    subject_name: str = typer.Option("subject", "--subject-name"),
    subject_digest: str = typer.Option(
        ..., "--subject-digest", help="sha256:… digest of the artifact the SBOM describes"
    ),
    out: str | None = typer.Option(None, "--out", help="Envelope path (default <sbom>.att)"),
    attach: str | None = typer.Option(
        None, "--attach", help="Image ref to attach the attestation to (referrers API)"
    ),
) -> None:
    """DSSE in-toto attestation bound to the subject digest."""
    from sorb.emit.signing import attest as make_attestation

    try:
        envelope = make_attestation(
            Path(sbom).read_bytes(),
            subject_name=subject_name,
            subject_digest=subject_digest,
            private_key_pem=Path(key).read_bytes(),
        )
        dest = Path(out) if out else Path(sbom + ".att")
        dest.write_bytes(envelope)
        typer.echo(f"  {dest} written (DSSE in-toto attestation)", err=True)
        if attach:
            from sorb.container.registry import RegistryClient
            from sorb.container.spec import parse_image_ref

            client = RegistryClient(parse_image_ref(attach))
            try:
                _doc, manifest_digest, _raw = client.fetch_manifest()
                pushed = client.attach_attestation(manifest_digest, envelope)
                typer.echo(f"  attached to {attach} as {pushed}", err=True)
            finally:
                client.close()
    except (SorbError, ValueError, OSError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e) if isinstance(e, SorbError) else 1) from e


@app.command()
def verify(
    artifact: str = typer.Argument(..., help="Attestation (.att) or signature bundle (.sig)"),
    key: str = typer.Option(..., "--key", help="Public key PEM (pinned-key identity policy)"),
    sbom: str | None = typer.Option(
        None,
        "--sbom",
        help="The artifact you hold: the signed file for a detached bundle, or the "
        "subject an attestation must be about. Use --subject-digest instead when "
        "you have the digest but not the bytes; passing both is an error unless "
        "they agree",
    ),
    subject_digest: str | None = typer.Option(None, "--subject-digest"),
    lineage: str | None = typer.Option(
        None, "--lineage", help="results index.json for lineage-consistency checking"
    ),
) -> None:
    """Ordered verification checks, each reported discretely."""
    import json as _json

    from sorb.emit.signing import verify as run_verify

    try:
        steps = run_verify(
            Path(artifact).read_bytes(),
            public_key_pem=Path(key).read_bytes(),
            expected_subject_digest=subject_digest,
            sbom_bytes=Path(sbom).read_bytes() if sbom else None,
            lineage_index=_json.loads(Path(lineage).read_text()) if lineage else None,
        )
    except (ValueError, OSError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1) from e
    failed = False
    for step in steps:
        mark = "○" if step.skipped else ("✔" if step.ok else "✘")
        typer.echo(f"  {mark} {step.name}: {step.detail}")
        failed = failed or not step.ok
    if failed:
        raise typer.Exit(EXIT_POLICY_FAIL)
    typer.echo("  verification passed")
