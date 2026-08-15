"""Out-of-process gRPC plugins.

For heavyweight integrations where WASM sandboxing is too restrictive — cloud
snapshot providers, proprietary registries — a plugin runs as a user-launched
process speaking versioned gRPC (`SourceProvider`, `Cataloger`; protos under
`sorb/plugin/proto/`). This is an **explicit trust decision**: unlike WASM, a
gRPC plugin runs with the host's privileges, so it is only contacted when the
user has named it in trusted config. Findings it returns are still re-validated
(`sorb.plugin.validation`) — trust the process, never its output blindly.

`grpcio` is an optional dependency (`sorbet[grpc]`). Messages are encoded by
`sorb.plugin.wire` rather than generated stubs, so installing the extra brings
in a transport and nothing else. Channels are TLS by default; plaintext is
opt-in per endpoint.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher
from sorb.errors import DetectorFailure, UsageError
from sorb.model import Finding
from sorb.plugin.validation import validate_findings_json
from sorb.plugin.wire import decode_findings_json, decode_globs, encode_analyze_request
from sorb.source.base import Entry

PROTO_VERSION = "v1"
_SERVICE = "/sorb.plugin.v1.Cataloger"
CALL_TIMEOUT_S = 30.0


@dataclass
class TrustConfig:
    """Which gRPC plugin endpoints the user has explicitly trusted."""

    trusted_endpoints: set[str] = field(default_factory=set)
    #: endpoints the user accepted in plaintext (loopback development)
    insecure_endpoints: set[str] = field(default_factory=set)

    def check(self, endpoint: str) -> None:
        if endpoint not in self.trusted_endpoints:
            raise UsageError(
                f"gRPC plugin {endpoint!r} is not in trusted config — refusing to contact it. "
                "Add it under [plugins.grpc] trusted = [...] to allow (explicit-trust gate)."
            )


class GrpcCataloger(Cataloger):
    """Client shim for a remote `Cataloger` gRPC service."""

    def __init__(self, namespace: str, endpoint: str, globs: list[str], trust: TrustConfig,
                 version: int = 1, channel: object | None = None) -> None:
        self.id = f"grpc/{namespace}"
        self.version = version
        self.matchers = [Matcher(glob=g) for g in globs]
        self._namespace = namespace
        self._endpoint = endpoint
        self._trust = trust
        self._channel = channel

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        self._trust.check(self._endpoint)
        try:
            raw = self._invoke(entry.path, entry.size, blob)
        except Exception as e:  # a dead/misbehaving plugin degrades to a gap
            raise DetectorFailure(f"grpc plugin {self._namespace} failed: {type(e).__name__}") from e
        yield from validate_findings_json(raw, namespace=self._namespace)

    def _invoke(self, path: str, size: int, blob: bytes) -> bytes:
        channel = self._channel or open_channel(self._endpoint, self._trust)
        call = channel.unary_unary(f"{_SERVICE}/Analyze")  # type: ignore[attr-defined]
        reply = call(encode_analyze_request(path, size, blob), timeout=CALL_TIMEOUT_S)
        return decode_findings_json(bytes(reply))


def matcher_globs(endpoint: str, trust: TrustConfig, channel: object | None = None) -> list[str]:
    """Ask a remote cataloger which paths it wants. Trust-gated like `parse`."""
    trust.check(endpoint)
    chan = channel or open_channel(endpoint, trust)
    call = chan.unary_unary(f"{_SERVICE}/MatcherGlobs")  # type: ignore[attr-defined]
    return decode_globs(bytes(call(b"", timeout=CALL_TIMEOUT_S)))


def open_channel(endpoint: str, trust: TrustConfig) -> object:  # pragma: no cover - needs grpcio
    try:
        import grpc
    except ImportError as e:
        raise UsageError("gRPC plugin support needs `pip install 'sorbet[grpc]'`") from e
    if endpoint in trust.insecure_endpoints:
        return grpc.insecure_channel(endpoint)
    return grpc.secure_channel(endpoint, grpc.ssl_channel_credentials())
