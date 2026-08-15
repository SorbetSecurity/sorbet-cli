"""OCI Distribution API client.

Registry-direct acquisition, no daemon needed:

- anonymous, HTTP basic, and bearer-token auth (challenge flow), with
  credentials from ``$DOCKER_CONFIG/config.json`` and **credential helpers**
  (the one sanctioned executable-invocation exception — helpers are invoked
  for auth tokens only, never for parsing);
- manifest **index** handling with ``--platform`` selection / platform listing
  for ``--all-platforms``;
- blob GETs (optionally ranged) verified against their digest and written
  through the content-addressed cache, so re-scans and sibling images never
  re-download shared layers;
- bounded retry with backoff on transport errors and 5xx;
- ``--offline`` is absolute: cached content is served, the network is never
  touched, anything missing is a typed `TargetError`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from sorb.cache import Cas
from sorb.container.image import (
    MT_DOCKER_LIST,
    MT_DOCKER_MANIFEST,
    MT_OCI_INDEX,
    MT_OCI_MANIFEST,
    ImageLayer,
    ResolvedImage,
    index_platforms,
    layers_from_manifest,
    load_json_bytes,
    select_manifest_from_index,
)
from sorb.container.spec import ImageRef
from sorb.errors import TargetError

_ACCEPT = ", ".join([MT_OCI_INDEX, MT_OCI_MANIFEST, MT_DOCKER_LIST, MT_DOCKER_MANIFEST])
_RETRIES = 2
_BACKOFF_BASE_S = 0.05


# -- credentials --------------------------------------------------------------------


def _docker_config_path() -> Path:
    env = os.environ.get("DOCKER_CONFIG")
    base = Path(env) if env else Path.home() / ".docker"
    return base / "config.json"


def _helper_credentials(helper: str, registry: str) -> tuple[str, str] | None:
    """Invoke ``docker-credential-<helper> get`` — auth-only executable exception."""
    try:
        proc = subprocess.run(
            [f"docker-credential-{helper}", "get"],
            input=registry.encode(),
            capture_output=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return None
        doc = json.loads(proc.stdout)
        username, secret = doc.get("Username"), doc.get("Secret")
        if username and secret:
            return str(username), str(secret)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    return None


def load_registry_credentials(registry: str) -> tuple[str, str] | None:
    """Resolve (user, secret) for a registry from docker config / helpers."""
    path = _docker_config_path()
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    aliases = [registry]
    if registry == "registry-1.docker.io":
        aliases += ["docker.io", "https://index.docker.io/v1/", "index.docker.io"]
    helpers = doc.get("credHelpers") or {}
    for alias in aliases:
        if alias in helpers:
            return _helper_credentials(str(helpers[alias]), alias)
    if doc.get("credsStore"):
        creds = _helper_credentials(str(doc["credsStore"]), registry)
        if creds:
            return creds
    auths = doc.get("auths") or {}
    for alias in aliases:
        entry = auths.get(alias) or auths.get(f"https://{alias}")
        if entry and entry.get("auth"):
            try:
                user, _, secret = base64.b64decode(entry["auth"]).decode().partition(":")
                if user and secret:
                    return user, secret
            except (ValueError, UnicodeDecodeError):
                continue
    return None


def _parse_challenge(header: str) -> dict[str, str]:
    """Parse a WWW-Authenticate header's scheme + params."""
    scheme, _, rest = header.partition(" ")
    params: dict[str, str] = {"scheme": scheme.lower()}
    for part in rest.split(","):
        key, sep, value = part.strip().partition("=")
        if sep:
            params[key.strip().lower()] = value.strip().strip('"')
    return params


class RegistryClient:
    """Client for one repository on one registry."""

    def __init__(
        self,
        ref: ImageRef,
        *,
        cas: Cas | None = None,
        offline: bool = False,
        transport: httpx.BaseTransport | None = None,
        insecure_http: bool = False,
    ) -> None:
        self.ref = ref
        self.cas = cas if cas is not None else Cas()
        self.offline = offline
        scheme = "http" if insecure_http else "https"
        self._client = httpx.Client(
            base_url=f"{scheme}://{ref.registry}",
            transport=transport,
            timeout=30.0,
            follow_redirects=True,
        )
        self._token: str | None = None
        self._basic: tuple[str, str] | None = None

    # -- HTTP with auth + retry -------------------------------------------------

    def _request(
        self, method: str, url: str, headers: dict[str, str], content: bytes | None = None
    ) -> httpx.Response:
        if self.offline:
            raise TargetError(
                f"--offline: registry access to {self.ref.registry} required but not cached"
            )
        last_error: Exception | None = None
        for attempt in range(_RETRIES + 1):
            try:
                resp = self._client.request(
                    method, url, headers=self._with_auth(headers), content=content
                )
                if resp.status_code == 401 and attempt == 0:
                    self._authenticate(resp.headers.get("www-authenticate", ""))
                    continue
                if resp.status_code >= 500:
                    last_error = TargetError(
                        f"registry error {resp.status_code} on {url} "
                        f"({self.ref.registry}, attempt {attempt + 1})"
                    )
                    time.sleep(_BACKOFF_BASE_S * (2**attempt))
                    continue
                if resp.status_code == 404:
                    raise TargetError(
                        f"{self.ref.familiar()}: not found on {self.ref.registry} ({url})"
                    )
                if resp.status_code >= 400:
                    raise TargetError(
                        f"registry error {resp.status_code} on {url} "
                        f"(auth {'present' if (self._token or self._basic) else 'absent'})"
                    )
                return resp
            except httpx.TransportError as e:
                last_error = e
                time.sleep(_BACKOFF_BASE_S * (2**attempt))
        raise TargetError(
            f"cannot reach registry {self.ref.registry}: {last_error}"
        ) from last_error

    def _with_auth(self, headers: dict[str, str]) -> dict[str, str]:
        out = dict(headers)
        if self._token:
            out["Authorization"] = f"Bearer {self._token}"
        elif self._basic:
            creds = base64.b64encode(f"{self._basic[0]}:{self._basic[1]}".encode()).decode()
            out["Authorization"] = f"Basic {creds}"
        return out

    def _authenticate(self, challenge_header: str) -> None:
        """Handle a 401: basic or bearer per the challenge."""
        challenge = _parse_challenge(challenge_header)
        creds = load_registry_credentials(self.ref.registry)
        if challenge.get("scheme") == "basic":
            if creds is None:
                raise TargetError(
                    f"{self.ref.registry} requires basic auth and no credentials were found "
                    "(docker login, or configure a credential helper)"
                )
            self._basic = creds
            return
        if challenge.get("scheme") == "bearer":
            realm = challenge.get("realm")
            if not realm:
                raise TargetError(f"malformed bearer challenge from {self.ref.registry}")
            params: dict[str, str] = {}
            if challenge.get("service"):
                params["service"] = challenge["service"]
            params["scope"] = challenge.get(
                "scope", f"repository:{self.ref.repository}:pull"
            )
            auth = creds if creds else None
            try:
                resp = self._client.get(realm, params=params, auth=auth)
            except httpx.TransportError as e:
                raise TargetError(f"token endpoint unreachable ({realm}): {e}") from e
            if resp.status_code >= 400:
                raise TargetError(
                    f"token endpoint {realm} refused ({resp.status_code}); "
                    "check credentials (docker login)"
                )
            doc = resp.json()
            token = doc.get("token") or doc.get("access_token")
            if not token:
                raise TargetError(f"token endpoint {realm} returned no token")
            self._token = str(token)
            return
        raise TargetError(
            f"unsupported auth scheme from {self.ref.registry}: {challenge.get('scheme')}"
        )

    # -- manifests -----------------------------------------------------------------

    def _manifest_cache_key(self, reference: str) -> str:
        return f"registry-manifest:{self.ref.registry}/{self.ref.repository}@{reference}"

    def fetch_manifest(self, reference: str | None = None) -> tuple[dict[str, Any], str, bytes]:
        """GET a manifest (tag or digest). Returns (doc, digest, raw bytes)."""
        reference = reference or self.ref.digest or self.ref.tag or "latest"
        cached = self.cas.get(self._manifest_cache_key(reference))
        if cached is not None:
            raw = cached
        elif self.offline:
            raise TargetError(
                f"--offline: manifest for {self.ref.familiar()} is not in the local cache"
            )
        else:
            resp = self._request(
                "GET",
                f"/v2/{self.ref.repository}/manifests/{reference}",
                {"Accept": _ACCEPT},
            )
            raw = resp.content
            self.cas.put(self._manifest_cache_key(reference), raw)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if reference.startswith("sha256:") and digest != reference:
            raise TargetError(
                f"manifest digest mismatch: asked {reference}, got {digest} — refusing"
            )
        doc = load_json_bytes(raw, f"manifest {reference}")
        # cache digest-addressed copy too, so offline digest lookups hit
        self.cas.put(self._manifest_cache_key(digest), raw)
        return doc, digest, raw

    def platforms(self) -> list[str]:
        doc, _digest, _raw = self.fetch_manifest()
        if "manifests" in doc:
            return index_platforms(doc)
        cfg = doc.get("config") or {}
        if cfg:
            config = load_json_bytes(self.fetch_blob(str(cfg["digest"])), "image config")
            return [f"{config.get('os', 'linux')}/{config.get('architecture', 'unknown')}"]
        return []

    # -- blobs ------------------------------------------------------------------------

    def fetch_blob(self, digest: str, *, byte_range: tuple[int, int] | None = None) -> bytes:
        """GET a blob by digest, CAS-first, digest-verified (ranged GETs bypass CAS)."""
        hexval = digest.partition(":")[2]
        if byte_range is None:
            cached = self.cas.get_blob(hexval)
            if cached is not None:
                return cached
            if self.offline:
                raise TargetError(f"--offline: blob {digest} is not in the local cache")
        headers: dict[str, str] = {}
        if byte_range is not None:
            headers["Range"] = f"bytes={byte_range[0]}-{byte_range[1]}"
        resp = self._request("GET", f"/v2/{self.ref.repository}/blobs/{digest}", headers)
        data = resp.content
        if byte_range is None:
            got = hashlib.sha256(data).hexdigest()
            if got != hexval:
                raise TargetError(f"blob digest mismatch for {digest} (got sha256:{got})")
            self.cas.put_blob(data)
        return data

    # -- push (--attach) -------------------------------------------------------------------

    def put_blob(self, data: bytes) -> str:
        """Monolithic blob upload. Returns the digest."""
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self._request(
            "POST",
            f"/v2/{self.ref.repository}/blobs/uploads/?digest={digest}",
            {"Content-Type": "application/octet-stream"},
            content=data,
        )
        self.cas.put_blob(data)
        return digest

    def put_manifest(self, reference: str, manifest: bytes, media_type: str) -> str:
        digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        self._request(
            "PUT",
            f"/v2/{self.ref.repository}/manifests/{reference}",
            {"Content-Type": media_type},
            content=manifest,
        )
        return digest

    def attach_attestation(self, subject_manifest_digest: str, envelope: bytes) -> str:
        """Attach a DSSE attestation to an image via the referrers channel
        (an OCI manifest whose `subject` names the image manifest)."""
        subject_raw = self.fetch_manifest(subject_manifest_digest)[2]
        env_digest = self.put_blob(envelope)
        empty = self.put_blob(b"{}")
        manifest = {
            "schemaVersion": 2,
            "mediaType": MT_OCI_MANIFEST,
            "artifactType": "application/vnd.dsse.envelope.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": empty,
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.dsse.envelope.v1+json",
                    "digest": env_digest,
                    "size": len(envelope),
                }
            ],
            "subject": {
                "mediaType": MT_OCI_MANIFEST,
                "digest": subject_manifest_digest,
                "size": len(subject_raw),
            },
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
        digest = self.put_manifest(
            f"sha256-{subject_manifest_digest.partition(':')[2]}.att",
            manifest_bytes,
            MT_OCI_MANIFEST,
        )
        return digest

    # -- referrers -----------------------------------------------------------------------

    def referrers(self, digest: str) -> list[dict[str, Any]]:
        """Referrers-API descriptors for a manifest digest; cosign tag fallback.

        Returns descriptor dicts; failures degrade to an empty list (referrers
        are an enrichment, never a scan blocker).

        The result is cached with the rest of the acquisition. A re-scan whose
        manifest and blobs all come from the cache would otherwise pay a TLS
        handshake and a token exchange purely to re-learn that an image has no
        attestations. `sorb cache clear` re-checks.
        """
        out: list[dict[str, Any]] = []
        if self.offline:
            return out
        cache_key = f"registry-referrers:{self.ref.registry}/{self.ref.repository}@{digest}"
        cached = self.cas.get(cache_key)
        if cached is not None:
            try:
                doc = load_json_bytes(cached, "cached referrers")
                return [d for d in doc.get("manifests", []) if isinstance(d, dict)]
            except TargetError:
                pass
        try:
            resp = self._request(
                "GET", f"/v2/{self.ref.repository}/referrers/{digest}", {"Accept": MT_OCI_INDEX}
            )
            doc = load_json_bytes(resp.content, "referrers response")
            out.extend(d for d in doc.get("manifests", []) if isinstance(d, dict))
            self.cas.put(cache_key, resp.content)
        except TargetError:
            pass
        if not out:
            # cosign tag schema fallback: sha256-<hex>.att / .sbom
            hexval = digest.partition(":")[2]
            for suffix in (".sbom", ".att"):
                try:
                    doc, tag_digest, _raw = self.fetch_manifest(f"sha256-{hexval}{suffix}")
                    out.append({"digest": tag_digest, "mediaType": doc.get("mediaType", ""), "_doc": doc})
                except TargetError:
                    continue
        return out

    # -- resolve to an image ----------------------------------------------------------------

    def resolve(self, platform: str | None) -> ResolvedImage:
        doc, digest, _raw = self.fetch_manifest()
        resolved_platform = platform
        if "manifests" in doc:
            desc, resolved_platform = select_manifest_from_index(doc, platform)
            doc, digest, _raw = self.fetch_manifest(str(desc["digest"]))
        config_desc = doc.get("config") or {}
        if not config_desc:
            raise TargetError(f"manifest for {self.ref.familiar()} has no config descriptor")
        config = load_json_bytes(self.fetch_blob(str(config_desc["digest"])), "image config")
        layers = layers_from_manifest(doc, config)

        def opener(layer: ImageLayer) -> bytes:
            return self.fetch_blob(layer.digest)

        cfg_os = str(config.get("os", "linux"))
        cfg_arch = str(config.get("architecture", "unknown"))
        return ResolvedImage(
            ref=self.ref.familiar(),
            digest=str(config_desc["digest"]),  # image ID (cross-acquisition identity)
            platform=resolved_platform or f"{cfg_os}/{cfg_arch}",
            manifest=doc,
            config=config,
            layers=layers,
            blob_opener=opener,
            provenance_facts={
                "acquisition": "registry",
                "registry": self.ref.registry,
                "repository": self.ref.repository,
                "manifest_digest": digest,
                "image_id": str(config_desc["digest"]),
            },
            annotations=dict(doc.get("annotations") or {}),
        )

    def close(self) -> None:
        self._client.close()
