# What & why

<!-- One or two sentences: what changes, and what a user or contributor gains. -->

## Checklist

- [ ] `ruff check src tests`, `mypy`, `lint-imports` and `pytest -q` pass locally
- [ ] Tests added/updated for any behavior change
- [ ] Detector/cataloger changes include a corpus fixture proving the new
      behavior (and a differential-ledger entry if a known disagreement with
      other tools changes)
- [ ] Anything touching the sandbox, signing, or plugin validation says what
      was tested and on which platform
