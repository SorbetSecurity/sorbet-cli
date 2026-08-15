"""End-to-end: `sorb scan` on container targets through the real CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))
from container_fixtures import (  # noqa: E402
    DPKG_STATUS_V1,
    DPKG_STATUS_V2,
    OS_RELEASE_DEBIAN,
    build_image,
    write_docker_archive,
    write_oci_layout,
)
from sorb.cli.main import app  # noqa: E402

runner = CliRunner()


@pytest.fixture()
def image_layout(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    bundle = build_image(
        [
            {
                "var/lib/dpkg/status": DPKG_STATUS_V1.encode(),
                "etc/os-release": OS_RELEASE_DEBIAN.encode(),
            },
            {"var/lib/dpkg/status": DPKG_STATUS_V2.encode()},
        ],
        history=["FROM debian:12", "apt-get upgrade -y"],
        ref_name="acme/api:1.2",
    )
    return write_oci_layout(bundle, tmp_path / "layout")


def test_cli_scan_oci_dir_writes_cyclonedx(image_layout: Path, tmp_path: Path) -> None:
    out = tmp_path / "sbom.json"
    res = runner.invoke(
        app,
        ["scan", f"oci-dir:{image_layout}", "-o", "cyclonedx-json", "-f", str(out)],
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text())
    comps = {c["name"]: c for c in doc["components"]}
    assert comps["curl"]["version"] == "8.5.0-1"
    props = {p["name"]: p["value"] for p in comps["curl"]["properties"]}
    assert props["sorb:layer-ordinal"] == "1"
    assert props["sorb:introduced-by"] == "RUN apt-get upgrade -y"
    assert props["sorb:layer"].startswith("sha256:")
    # the pkgdb-upgrade annotation rides into the SBOM properties
    assert any(name.startswith("sorb:annotation:pkgdb-upgraded") for name in props)


def test_cli_scan_docker_archive_summary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    bundle = build_image(
        [{"var/lib/dpkg/status": DPKG_STATUS_V2.encode(), "etc/os-release": OS_RELEASE_DEBIAN.encode()}],
        ref_name="acme/api:1.2",
    )
    archive = write_docker_archive(bundle, tmp_path / "api.tar")
    res = runner.invoke(app, ["scan", f"docker-archive:{archive}", "-o", "summary"])
    assert res.exit_code == 0, res.output
    assert "components:" in res.output
    assert "deb=2" in res.output


def test_cli_include_removed_flag(image_layout: Path, tmp_path: Path) -> None:
    out = tmp_path / "with-removed.json"
    res = runner.invoke(
        app,
        [
            "scan", f"oci-dir:{image_layout}",
            "--include-removed",
            "-o", "cyclonedx-json", "-f", str(out),
        ],
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text())
    comps = {(c["name"], c.get("version")): c for c in doc["components"]}
    removed = comps[("leftme", "1.0-1")]
    props = {p["name"]: p["value"] for p in removed["properties"]}
    assert props["sorb:state"] == "removed"


def test_cli_scan_exit_codes_disjoint(image_layout: Path) -> None:
    ok = runner.invoke(app, ["scan", f"oci-dir:{image_layout}", "-o", "summary"])
    assert ok.exit_code == 0
    missing = runner.invoke(app, ["scan", "oci-dir:/nope/definitely-missing"])
    assert missing.exit_code == 1
    assert "not an OCI image layout" in missing.output
