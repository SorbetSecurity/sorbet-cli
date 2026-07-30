"""SPA is served self-contained and offline.

A "test proxy" style assertion without a real proxy: the shipped HTML/JS/CSS must
reference no external origin, and the server's CSP must forbid one. Combined, an
air-gapped load is structurally guaranteed. Runs in-process (no socket bound).
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.ui.config import ServerConfig
from sorb.ui.server import create_app

_EXTERNAL = re.compile(r"""(?:src|href)\s*=\s*["'](https?:|//)""", re.I)
_FETCH_EXTERNAL = re.compile(r"""(?:fetch|EventSource|import|url)\(\s*["']https?://""", re.I)


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    fixture = Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot"
    proj = tmp_path / "polyglot"
    shutil.copytree(fixture, proj, ignore=shutil.ignore_patterns(".sorb"))
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, store_path=tmp_path / "run.sorb.db")
    config = ServerConfig(run=str(result.store_path), target=str(proj), extra_allowed_hosts=("testserver",))
    c = TestClient(create_app(config))
    c.headers.update({"Authorization": f"Bearer {config.token}"})
    return c


def test_index_is_self_contained(client: TestClient) -> None:
    html = client.get("/").text
    assert "<title>" in html and "/assets/app.js" in html
    assert not _EXTERNAL.search(html), "index.html must reference no external origin"


def test_assets_served_with_types(client: TestClient) -> None:
    js = client.get("/assets/app.js")
    css = client.get("/assets/app.css")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert css.status_code == 200 and "css" in css.headers["content-type"]
    assert not _FETCH_EXTERNAL.search(js.text), "app.js must not fetch an external origin"
    assert "http://" not in css.text and "https://" not in css.text


def test_csp_forbids_external_origins(client: TestClient) -> None:
    csp = client.get("/").headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    # no scheme-host source is ever allowed
    assert "http://" not in csp and "https://" not in csp and "*" not in csp


def test_asset_path_traversal_blocked(client: TestClient) -> None:
    assert client.get("/assets/../server.py").status_code in (400, 404)
    assert client.get("/assets/..%2f..%2fetc%2fpasswd").status_code in (400, 404)


def test_favicon_is_inline_data_uri(client: TestClient) -> None:
    html = client.get("/").text
    icon = re.search(r'rel="icon"\s+href="([^"]+)"', html)
    assert icon and icon.group(1).startswith("data:"), "favicon must be inline, not a remote fetch"
