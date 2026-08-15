#!/bin/bash -eu
# OSS-Fuzz build script. Compiles one atheris fuzzer per target in
# sorb.fuzz.FUZZ_TARGETS. Invoked by OSS-Fuzz's infra with $OUT / $SRC set.
#
# Not run in the offline dev tree (needs the OSS-Fuzz base image + atheris);
# committed as the integration contract.

pip install --no-cache-dir "$SRC/sorbet-cli"

TARGETS="binary regf fat rpm-header hcl tar safetensors gguf certificate dpkg partition"

for target in $TARGETS; do
  out="$OUT/fuzz_${target//-/_}"
  cat > "$out.py" <<PY
import atheris, sys
from sorb.fuzz import atheris_main
if __name__ == "__main__":
    atheris_main("$target")
PY
  compile_python_fuzzer "$out.py"
  # seed corpus
  python - "$target" "$OUT" <<'PY'
import sys, zipfile, os
from sorb.fuzz import seed_corpus
target, out = sys.argv[1], sys.argv[2]
seeds = seed_corpus().get(target, [])
z = zipfile.ZipFile(os.path.join(out, f"fuzz_{target.replace('-','_')}_seed_corpus.zip"), "w")
for i, s in enumerate(seeds):
    z.writestr(f"seed{i}", s)
z.close()
PY
done
