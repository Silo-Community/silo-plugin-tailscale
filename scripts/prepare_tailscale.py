#!/usr/bin/env python3
"""Recreate the pinned Tailscale source with two audited storage adaptations.

Verify archive contents against committed go.sum, never trust extracted module
caches or an existing .build tree. Exact-match edits fail on upstream drift.
"""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import zipfile


def pinned_version(go_mod):
    """Read the Tailscale version from go.mod, the only place it is pinned."""
    versions = re.findall(r"^\s*tailscale\.com (v\S+)", go_mod.read_text(encoding="utf-8"), re.MULTILINE)
    if len(versions) != 1:
        raise ValueError("go.mod must require tailscale.com exactly once")
    return versions[0]


VERSION = pinned_version(Path(__file__).resolve().parents[1] / "go.mod")


def extract_verified_module(archive, output, expected_sum):
    """Verify Go's h1 directory hash before extracting a module archive."""
    prefix = f"tailscale.com@{VERSION}/"
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate module archive entry")
        digest = hashlib.sha256()
        for name in sorted(names):
            relative = name.removeprefix(prefix)
            if (not name.startswith(prefix) or not relative or "\n" in name
                    or "\\" in name or PurePosixPath(relative).is_absolute()
                    or ".." in PurePosixPath(relative).parts or name.endswith("/")):
                raise ValueError(f"Invalid module archive path: {name!r}")
            file_hash = hashlib.sha256(bundle.read(name)).hexdigest()
            digest.update(f"{file_hash}  {name}\n".encode())
        actual_sum = "h1:" + base64.b64encode(digest.digest()).decode()
        if actual_sum != expected_sum:
            raise ValueError("Tailscale archive checksum does not match committed go.sum")
        for name in names:
            target = output / name.removeprefix(prefix)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(name))
            target.chmod(0o644)


def patch(output, path, edits):
    target = output / path
    text = target.read_text(encoding="utf-8")
    for before, after in edits:
        if text.count(before) != 1:
            raise ValueError(f"Upstream drift in {path}: {before[:60]!r}")
        text = text.replace(before, after, 1)
    target.write_text(text, encoding="utf-8")


def adapt_source(output):
    patch(output, 'tsnet/tsnet.go', [
        (
            '\ts.rootPath = s.Dir',
            '\ts.rootPath = s.Dir\n'
            '\tif s.NoLocalState { s.rootPath = "" }',
        ),
        (
            'type Server struct {',
            'type Server struct {\n'
            '\t// NoLocalState requires an external Store and disables local files and logtail.\n'
            '\tNoLocalState bool\n',
        ),
        (
            '\tif s.rootPath == "" {\n'
            '\t\tconfDir',
            '\tif s.NoLocalState && s.Store == nil {\n'
            '\t\treturn errors.New("NoLocalState requires an external Store")\n'
            '\t}\n'
            '\tif !s.NoLocalState {\n'
            '\tif s.rootPath == "" {\n'
            '\t\tconfDir',
        ),
        (
            '\n'
            '\ttsLogf := func(format string, a ...any) {',
            '\n'
            '\t}\n'
            '\n'
            '\ttsLogf := func(format string, a ...any) {',
        ),
        (
            '\tif testenv.InTest() {\n'
            '\t\treturn nil\n'
            '\t}\n'
            '\tcfgPath',
            '\tif s.NoLocalState || testenv.InTest() {\n'
            '\t\treturn nil\n'
            '\t}\n'
            '\tcfgPath',
        ),
    ])
    patch(output, 'feature/acme/certstore.go', [
        (
            '\tdefault:\n'
            '\t\tif hostinfo.GetEnvType() == hostinfo.Kubernetes {\n'
            "\t\t\t// We're running in Kubernetes with a custom StateStore,\n"
            '\t\t\t// use that instead of the cert directory.\n'
            '\t\t\t// TODO(maisem): expand this to other environments?\n'
            '\t\t\treturn certStateStore{StateStore: st}, nil\n'
            '\t\t}',
            '\tdefault:\n'
            '\t\treturn certStateStore{StateStore: st}, nil',
        ),
        (
            '\n'
            '\t"tailscale.com/hostinfo"',
            '',
        ),
    ])


def prepare(root):
    sums = [line.split()[2] for line in (root / "go.sum").read_text(encoding="utf-8").splitlines()
            if line.startswith(f"tailscale.com {VERSION} ")]
    if len(sums) != 1:
        raise ValueError("Tailscale must have exactly one committed checksum before download")
    environment = {**os.environ, "GOFLAGS": "", "GOWORK": "off"}
    module = json.loads(subprocess.check_output(
        ["go", "mod", "download", "-json", "tailscale.com"], cwd=root, env=environment))
    if module.get("Version") != VERSION or module.get("Replace"):
        raise ValueError("Downloaded Tailscale module does not match go.mod")
    if module.get("Sum") != sums[0]:
        raise ValueError("Tailscale download checksum does not match committed go.sum")
    build = root / ".build"
    build.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tailscale-", dir=build) as temporary:
        output = Path(temporary) / "source"
        extract_verified_module(module["Zip"], output, sums[0])
        adapt_source(output)
        shutil.copyfile(root / "scripts" / "acme_state_test.go.txt",
                        output / "feature" / "acme" / "silo_state_test.go")
        subprocess.run(["gofmt", "-w", "tsnet/tsnet.go", "feature/acme/certstore.go",
                        "feature/acme/silo_state_test.go"], cwd=output, check=True)
        destination = build / "tailscale"
        if destination.is_symlink():
            raise ValueError("Refusing a symlink at .build/tailscale")
        if destination.exists():
            # Older preparations retained the module cache root permission (0555).
            destination.chmod(0o755)
            shutil.rmtree(destination)
        output.rename(destination)
    (build / "go.mod").write_text((root / "go.mod").read_text(encoding="utf-8")
                                + "\nreplace tailscale.com => ./.build/tailscale\n", encoding="utf-8")
    shutil.copyfile(root / "go.sum", build / "go.sum")


if __name__ == "__main__":
    prepare(Path(__file__).resolve().parents[1])
