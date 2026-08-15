"""Windows sandbox — not implemented.

Confining a child on Windows needs the process to be *created* with a
restricted token inside a job object (`CreateProcessAsUser` plus
`AssignProcessToJobObject`), or an AppContainer profile. `subprocess` cannot
adopt a foreign token after the fact, so there is no way to build this on top
of the shared `_popen` machinery.

Rather than run the build tool with the caller's full token and call it
sandboxed, this reports unavailable: `--resolve=native` then refuses on Windows
unless the user passes `--dangerously-no-sandbox`, which still applies the
scrubbed environment. The pure resolvers are the default and need no sandbox.
"""

from __future__ import annotations

import sys

from sorb.dynamic.sandbox.spec import BrokerResult, SandboxSpec


def windows_sandbox_available() -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "not Windows"
    return False, (
        "the Windows sandbox is not implemented (a restricted token has to be applied at "
        "process creation) — use the default pure resolvers, or accept the risk with "
        "--dangerously-no-sandbox"
    )


def run_windows_sandboxed(spec: SandboxSpec, argv: list[str]) -> BrokerResult:
    raise NotImplementedError(
        "no Windows sandbox: run_sandboxed must refuse before reaching this path"
    )
