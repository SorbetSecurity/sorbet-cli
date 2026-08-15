# ghcr.io/sorbetsecurity/sorb — the sorb scanner image.
# Multi-stage: build a wheel, install into a slim runtime. Offline-first: the
# image carries no telemetry and needs no network to scan a mounted target.
FROM python:3.13-slim AS build
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.13-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/SorbetSecurity/sorbet-cli"
LABEL org.opencontainers.image.description="Evidence-backed dependency analysis and SBOM generation"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl \
    && useradd --create-home --uid 1000 sorb
USER sorb
WORKDIR /work
ENTRYPOINT ["sorb"]
CMD ["--help"]
