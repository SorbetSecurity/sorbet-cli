# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub private vulnerability reporting](https://github.com/SorbetSecurity/sorbet-cli/security/advisories/new)
— not in a public issue.

You can expect an acknowledgement within a few days. Please include a
reproduction and the `sorb --version` output where applicable.

## Scope

Of particular interest, given what `sorb` promises:

- escapes from the native-mode sandbox (`--resolve=native`, `sorb trace`)
- credentials or other secrets reaching emitted SBOMs, scan databases, or logs
- WASM/gRPC plugin isolation bypasses, or plugins injecting unvalidated claims
- signature/attestation verification bypasses (`sorb sign` / `attest` / `verify`)
- network access happening without `--allow-net`

## Supported versions

Security fixes land on `main` and ship in the next release; only the latest
release is supported.
