# PyInstaller one-file spec for the standalone sorb bundle.
# Built in release CI on Linux/macOS/Windows; the resulting binary needs no
# Python. Data files (migrations, warnings.toml, base_rates.toml, UI assets,
# plugin proto, release key) are bundled so an air-gapped install is complete.
# Not run in the offline dev tree — CI produces the artifacts.
# ruff: noqa
# type: ignore
from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("sorb", includes=[
    "graph/migrations/*.sql", "data/*.toml", "data/*.pem",
    "ui/assets/*", "ui/assets/**/*", "plugin/proto/*.proto",
])

a = Analysis(
    ["../src/sorb/cli/main.py"],
    pathex=["../src"],
    datas=datas,
    hiddenimports=[
        "sorb.catalogers.base",  # entry-point registry loads submodules dynamically
    ],
    excludes=["fastapi", "uvicorn", "wasmtime", "grpc"],  # optional extras stay optional
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas,
    name="sorb",
    console=True,
    strip=True,
    upx=False,
    onefile=True,
)
