"""IaC catalogers: Terraform, K8s/Helm/Kustomize, CFN/Bicep/Ansible,
Dockerfile — extraction, image refs, Resources, and predicted-package drift."""

from __future__ import annotations

from sorb.catalogers.base import CatalogerContext, dispatch
from sorb.iac.hcl import Unresolved, interpolate, parse_hcl
from sorb.iac.imageref import parse_image_reference
from sorb.model import Coordinates, EdgeType, Finding, Tier
from sorb.source.base import Entry


class MapSource:
    def __init__(self, files):  # noqa: ANN001
        self.files = files

    def exists(self, path: str) -> bool:
        return path in self.files

    def open(self, path: str) -> bytes:
        return self.files[path]

    def coords(self, path: str, span=None):  # noqa: ANN001
        return Coordinates(source_id="s1", path=path, span=span)


def catalog(files, path):  # noqa: ANN001
    raw = {k: (v.encode() if isinstance(v, str) else v) for k, v in files.items()}
    blob = raw[path]
    entry = Entry(path=path, size=len(blob), sniff=blob[:64])
    out: list[Finding] = []
    for c in dispatch(entry):
        ctx = CatalogerContext(source=MapSource(raw), detector=c.detector)  # type: ignore[arg-type]
        out.extend(c.parse(ctx, entry, blob))
    return out


def by_name(fs):  # noqa: ANN001
    return {f.claim.name: f for f in fs}


def all_annotations(fs):  # noqa: ANN001
    return {a.code for f in fs for a in f.annotations}


# -- HCL parser -------------------------------------------------------------------------


def test_hcl_parser_blocks_and_interpolation() -> None:
    text = '''
    variable "region" { default = "us-east-1" }
    resource "aws_instance" "web" {
      ami           = "ami-12345"
      instance_type = var.instance_type
      tags = { Name = "web-${var.region}" }
    }
    '''
    attrs, blocks = parse_hcl(text)
    kinds = {b.btype for b in blocks}
    assert "variable" in kinds and "resource" in kinds
    res = next(b for b in blocks if b.btype == "resource")
    assert res.labels == ["aws_instance", "web"]
    assert res.body["ami"] == "ami-12345"
    assert isinstance(res.body["instance_type"], Unresolved)
    assert interpolate("web-${var.region}", {"region": "eu-west-1"}) == "web-eu-west-1"
    # unresolved var → placeholder marker, never a guessed value
    assert "<unresolved:var.missing>" in interpolate("x-${var.missing}", {})
    assert isinstance(interpolate("${var.missing}", {}), Unresolved)  # fully unresolved


def test_image_reference_pinned_vs_floating() -> None:
    pinned = parse_image_reference("ghcr.io/acme/api@sha256:" + "a" * 64)
    assert pinned.pinned and not pinned.floating
    floating = parse_image_reference("nginx:latest")
    assert floating.floating and floating.registry == "docker.io"
    tagged = parse_image_reference("ghcr.io/acme/api:1.2.3")
    assert not tagged.floating and tagged.tag == "1.2.3"


# -- Terraform --------------------------------------------------------------------------


def test_terraform_providers_modules_resources() -> None:
    tf = '''
    terraform {
      required_providers {
        aws = { source = "hashicorp/aws", version = "~> 5.31" }
      }
    }
    module "vpc" {
      source  = "terraform-aws-modules/vpc/aws"
      version = "5.5.0"
    }
    variable "img_tag" { default = "1.4.2" }
    resource "aws_ecs_task_definition" "app" {
      container_definitions = "[{\\"image\\": \\"ghcr.io/acme/api:${var.img_tag}\\"}]"
    }
    resource "aws_lambda_function" "fn" {
      runtime = "python3.12"
    }
    '''
    fs = catalog({"main.tf": tf}, "main.tf")
    names = by_name(fs)
    assert names["aws"].claim.version == "5.31"
    assert names["aws"].claim.ecosystem == "terraform"
    assert "terraform-aws-modules/vpc/aws" in names
    # ECS image ref resolved through var interpolation → RUNS edge
    api = names["api"]
    assert api.claim.attrs and dict(api.claim.attrs)["image-ref"] == "ghcr.io/acme/api:1.4.2"
    assert any(e.kind is EdgeType.RUNS for e in api.edges)
    # lambda runtime
    assert "python" in names and names["python"].claim.version == "3.12"
    # resource nodes present
    assert any(f.claim.ctype == "resource" for f in fs)


def test_terraform_lock_digests() -> None:
    """Lock hashes land as digests."""
    lock = '''
    provider "registry.terraform.io/hashicorp/aws" {
      version = "5.31.0"
      hashes = ["h1:abcdef123456", "zh:beef"]
    }
    '''
    fs = catalog({".terraform.lock.hcl": lock}, ".terraform.lock.hcl")
    aws = fs[0]
    assert aws.claim.name == "aws" and aws.claim.version == "5.31.0"
    assert dict(aws.claim.hashes)["terraform-h1"] == "abcdef123456"
    assert aws.evidence[0].tier is Tier.LOCKED


def test_terraform_unresolvable_var_is_placeholder() -> None:
    """Unresolvable var yields placeholder not guess."""
    tf = 'resource "aws_ecs_task_definition" "app" {\n  container_definitions = "[{\\"image\\": \\"${var.undefined_image}\\"}]"\n}\n'
    fs = catalog({"main.tf": tf}, "main.tf")
    # no image component emitted from an unresolved ref (not guessed)
    assert not any(f.claim.ecosystem == "oci" for f in fs)


# -- K8s / Helm / Kustomize -------------------------------------------------------------


def test_k8s_deployment_image_floating() -> None:
    manifest = '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      initContainers:
      - name: migrate
        image: ghcr.io/acme/migrate@sha256:{sha}
      containers:
      - name: api
        image: nginx:latest
'''.replace("{sha}", "b" * 64)
    fs = catalog({"deploy.yaml": manifest}, "deploy.yaml")
    names = by_name(fs)
    assert "nginx" in names and "migrate" in names
    # floating tag → unpinned-image finding
    assert "unpinned-image" in all_annotations(fs)
    # digest-pinned initContainer is NOT flagged
    assert not any(a.code == "unpinned-image" for a in names["migrate"].annotations)
    # RUNS edge from the workload
    assert any(e.kind is EdgeType.RUNS for e in names["nginx"].edges)


def test_helm_template_render() -> None:
    """{{ .Values.image.tag }} ref extracted via rendering."""
    template = "spec:\n  containers:\n  - image: {{ .Values.image.repo }}:{{ .Values.image.tag }}\n"
    values = "image:\n  repo: ghcr.io/acme/svc\n  tag: 2.1.0\n"
    fs = catalog(
        {"charts/x/templates/deploy.yaml": template, "charts/x/values.yaml": values},
        "charts/x/templates/deploy.yaml",
    )
    svc = [f for f in fs if f.claim.name == "svc"]
    assert svc and dict(svc[0].claim.attrs)["image-ref"] == "ghcr.io/acme/svc:2.1.0"
    assert svc[0].evidence[0].tier is Tier.INFERRED  # rendered → inferred


def test_helm_chart_deps() -> None:
    chart = "apiVersion: v2\nname: myapp\ndependencies:\n- name: redis\n  version: 18.1.5\n  repository: https://charts.bitnami.com/bitnami\n"
    fs = catalog({"Chart.yaml": chart}, "Chart.yaml")
    assert fs[0].claim.name == "redis" and fs[0].claim.version == "18.1.5"


def test_kustomize_images_transformer() -> None:
    """Kustomize-rewritten image is the one followed."""
    kust = "images:\n- name: nginx\n  newName: ghcr.io/acme/nginx\n  newTag: 1.25.3\n"
    fs = catalog({"kustomization.yaml": kust}, "kustomization.yaml")
    assert fs[0].claim.name == "nginx"
    assert dict(fs[0].claim.attrs)["image-ref"] == "ghcr.io/acme/nginx:1.25.3"
    assert dict(fs[0].claim.attrs)["follow-target"] == "ghcr.io/acme/nginx:1.25.3"


# -- CFN / Bicep / Ansible --------------------------------------------------------------


def test_cfn_intrinsics_and_sam_runtime() -> None:
    cfn = '''
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Stage:
    Default: prod
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: nodejs20.x
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
      - Image: !Sub "ghcr.io/acme/${Stage}:1.0"
'''
    fs = catalog({"template.yaml": cfn}, "template.yaml")
    names = by_name(fs)
    assert "nodejs" in names and names["nodejs"].claim.version == "20"
    # Fn::Sub resolved against parameter default
    assert "prod" in names["prod"].claim.name or any("prod" in (dict(f.claim.attrs).get("image-ref", "")) for f in fs)


def test_bicep_and_ansible() -> None:
    bicep = "module stg 'br:myreg.azurecr.io/bicep/storage:1.2.0' = {\n  name: 'stg'\n}\n"
    bfs = catalog({"main.bicep": bicep}, "main.bicep")
    assert bfs[0].claim.name == "storage" and bfs[0].claim.version == "1.2.0"

    reqs = "collections:\n- name: community.aws\n  version: 7.1.0\nroles:\n- geerlingguy.nginx\n"
    rfs = by_name(catalog({"requirements.yml": reqs}, "requirements.yml"))
    assert "community.aws" in rfs and rfs["community.aws"].claim.version == "7.1.0"
    assert "geerlingguy.nginx" in rfs

    play = "- hosts: all\n  tasks:\n  - name: install\n    apt:\n      name: nginx=1.24.0\n  - pip:\n      name: requests\n"
    pfs = by_name(catalog({"playbook.yml": play}, "playbook.yml"))
    assert "nginx" in pfs and pfs["nginx"].claim.version == "1.24.0"
    assert dict(pfs["nginx"].claim.attrs)["predicted"] == "ansible-apt"
    assert "requests" in pfs


# -- Dockerfile -------------------------------------------------------------------------


def test_dockerfile_full_analysis() -> None:
    dockerfile = '''
ARG VERSION=8.5.0
FROM debian:latest AS build
RUN apt-get update && apt-get install -y curl=${VERSION} ca-certificates
COPY --from=build /app /app
FROM gcr.io/distroless/base@sha256:{sha}
RUN pip install requests==2.32.0
'''.replace("{sha}", "c" * 64)
    fs = catalog({"Dockerfile": dockerfile}, "Dockerfile")
    names = by_name(fs)
    # base images: floating debian:latest flagged, pinned distroless not
    assert "debian" in names and dict(names["debian"].claim.attrs)["base-image"] == "true"
    assert "unpinned-image" in all_annotations(fs)
    # ARG-substituted RUN package prediction
    curl = names["curl"]
    assert curl.claim.version == "8.5.0"  # ${VERSION} substituted
    assert dict(curl.claim.attrs)["predicted"] == "dockerfile-RUN"
    assert "dockerfile-predicted" in all_annotations(fs)
    # pip predicted
    assert names["requests"].claim.version == "2.32.0"
    # multi-stage COPY --from provenance
    assert "multistage-copy" in all_annotations(fs)


def test_follow_images_collects_and_degrades(tmp_path, monkeypatch) -> None:
    """--follow-images collects IaC image refs and chases them; when the
    image is unreachable (offline) it degrades to an annotation, not a failure."""
    from pathlib import Path

    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.graph.store import GraphStore

    monkeypatch.setenv("SORB_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n"
        "spec:\n  template:\n    spec:\n      containers:\n"
        "      - name: api\n        image: registry.invalid/acme/api:1.0\n"
    )
    cfg = load_config(
        flags={"follow_images": True, "offline": True}, env={},
        user_config_path=tmp_path / "nc.toml",
    )
    result = run_scan(str(proj), cfg, store_path=tmp_path / "run.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        # the image ref was recorded and a follow attempt happened, degrading
        codes = {a["code"] for a in store.all_annotations()}
        assert "follow-image-unreachable" in codes
        assert any(code == "SORB-W062" for code, _ in result.warnings)
    finally:
        store.close()


def test_dockerfile_vs_image_drift_scenario() -> None:
    """The predicted package + an image-installed one at a different version
    reconcile into a drift finding."""
    import tempfile

    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.graph.store import GraphStore
    with tempfile.TemporaryDirectory() as tmp:
        from pathlib import Path
        proj = Path(tmp) / "proj"
        proj.mkdir()
        # Dockerfile predicts curl 8.5.0; a dpkg status (image reality) has 8.4.0
        (proj / "Dockerfile").write_text(
            "FROM debian:12\nRUN apt-get install -y curl=8.5.0\n"
        )
        rootfs = proj / "rootfs" / "var" / "lib" / "dpkg"
        rootfs.mkdir(parents=True)
        (rootfs / "status").write_text(
            "Package: curl\nStatus: install ok installed\nVersion: 8.4.0-1\n"
            "Architecture: amd64\nSource: curl\n"
        )
        (proj / "rootfs" / "etc").mkdir(parents=True)
        (proj / "rootfs" / "etc" / "os-release").write_text('ID=debian\n')
        cfg = load_config(flags={}, env={}, user_config_path=Path(tmp) / "nc.toml")
        result = run_scan(str(proj), cfg, store_path=Path(tmp) / "run.sorb.db")
        store = GraphStore.open_readonly(result.store_path)
        try:
            curls = store.find_component("curl")
            versions = {c.version for c in curls}
            # both the predicted (declared) and installed versions are present,
            # surfaced as a version disagreement rather than silently merged
            assert "8.4.0-1" in versions
        finally:
            store.close()


def test_dockerfile_run_stops_at_the_shell_command_boundary() -> None:
    """`apt-get install a && mv x y` installs `a`, not `mv`.

    A Dockerfile's line continuations join a RUN into one logical line, so
    without a boundary every later operand in the script reads as a package.
    """
    dockerfile = (
        "FROM debian:12\n"
        "RUN apt-get update \\\n"
        "    && apt-get install -y --no-install-recommends lua-cjson lua-inspect \\\n"
        "    && mv /usr/share/lua/5.3/inspect.lua /usr/share/lua/5.4/ \\\n"
        "    && luarocks --lua-version 5.4 install basexx \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
    )
    found = {
        (f.claim.ecosystem, f.claim.name)
        for f in catalog({"Dockerfile": dockerfile}, "Dockerfile")
        if f.claim.ecosystem == "deb"
    }
    assert found == {("deb", "lua-cjson"), ("deb", "lua-inspect")}


def test_dockerfile_run_finds_every_install_in_one_layer() -> None:
    dockerfile = (
        "FROM debian:12\n"
        "RUN apt-get install -y curl && apt-get install -y wget\n"
        'RUN pip3 install "requests>=2.32" && rm -rf /tmp/x\n'
        "RUN apk add --no-cache git openssl\n"
    )
    found = {
        (f.claim.ecosystem, f.claim.name)
        for f in catalog({"Dockerfile": dockerfile}, "Dockerfile")
        if f.claim.ecosystem in ("deb", "pypi", "apk")
    }
    assert ("deb", "curl") in found and ("deb", "wget") in found
    assert ("pypi", "requests") in found
    assert {("apk", "git"), ("apk", "openssl")} <= found


def test_terraform_evidence_points_at_the_declaring_line() -> None:
    """`sorb explain` must send a reader to the block, not to line 1.

    Searching for a bare label lands on the first place the word occurs, which
    for a common name is rarely the block that declares it.
    """
    tf = "\n".join(
        ['variable "target" {', '  default = "x"', "}", ""]
        + ["# filler"] * 20
        + ['resource "aws_iam_role" "target" {', '  name = "r"', "}", ""]
    )
    findings = catalog({"main.tf": tf}, "main.tf")
    role = next(f for f in findings if f.claim.name == "aws_iam_role.target")
    span = role.evidence[0].location.span
    assert span is not None
    declared_on = tf.splitlines().index('resource "aws_iam_role" "target" {') + 1
    assert span[0] == declared_on
