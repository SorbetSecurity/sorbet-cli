# Fuzzing

Every **byte**-parser sorbet ships has a fuzz target in `sorb.fuzz.FUZZ_TARGETS`
(binary ELF/PE/Mach-O/WASM, tar, registry hive, rpm headers, HCL, FAT,
partition tables, model headers, dpkg stanzas, certificates). Two harnesses
share those targets and their seed corpora:

- **In-process smoke fuzz** (`sorb.fuzz.smoke_fuzz`) - deterministic, runs in the
  test suite (`tests/unit/test_fuzz.py`). It mutates seeds and asserts the
  containment contract: a pathological file may make a parser *raise* (the
  pipeline catches it) but must never stack-overflow, exhaust memory, or hang.
  This is the CI smoke-fuzz budget per PR.
- **Coverage-guided fuzz** (`atheris`) - for deep, continuous fuzzing. Each target
  is exposed via `sorb.fuzz.atheris_main("<target>")`; the Rust crate's
  `cargo-fuzz` targets mirror them so both share seeds.

Structured-text parsers (lockfiles, manifests) are not fuzzed here: their
inputs are JSON/TOML/YAML that a library has already validated, so the risk is
in the resolution logic on top rather than in byte handling. The same
never-hang contract still applies to them, enforced by the suite-wide pytest
timeout and by targeted regression tests.

## Run locally

```bash
# deterministic smoke fuzz (in the test suite)
.venv/bin/pytest tests/unit/test_fuzz.py

# coverage-guided (needs: pip install atheris)
python -c "from sorb.fuzz import atheris_main; atheris_main('regf')" -- -runs=100000
```

## OSS-Fuzz integration

`oss_fuzz_build.sh` builds one atheris binary per target. The OSS-Fuzz project
config points `PROJECT_SRC` at this repo; corpora seed from `seed_corpus()`.

## Crash triage

1. OSS-Fuzz reports a reproducer input for `<target>`.
2. Reproduce: `python -c "from sorb.fuzz import run_once; print(run_once('<target>', open('repro','rb').read()))"`.
3. A returned `Crash(kind=…)` names the failure class: `recursion` (add a depth
   cap), `memory` (bound the allocation from a header-declared size - the common
   ML/GGUF/rpm bug), `hang` (bound the loop), `uncontained` (should never happen -
   the pipeline catches `Exception`).
4. Fix the parser, add the reproducer to the regression corpus in
   `tests/unit/test_fuzz.py::test_known_edge_case_regression_corpus`, confirm it
   runs green. **New-parser DoD hook:** a new parser ships with a fuzz target +
   seeds in the same PR.
