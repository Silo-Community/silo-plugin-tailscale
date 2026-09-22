#!/usr/bin/env python3
"""Build reproducible, verified release archives for supported platforms."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

PLATFORMS = (("linux", "amd64"), ("linux", "arm64"), ("darwin", "arm64"))
ARCHIVE_TIME = (1980, 1, 1, 0, 0, 0)
ARCHIVE_FILES = {"plugin", "manifest.json", "LICENSE", "LICENSE.tailscale", "THIRD_PARTY_NOTICES.txt"}


def validate_version(version):
    number = r"(?:0|[1-9][0-9]*)"
    identifier = rf"(?:{number}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    if not re.fullmatch(rf"{number}\.{number}\.{number}(?:-{identifier}(?:\.{identifier})*)?", version):
        raise ValueError("Version must be a semantic version without a v prefix or build metadata")


def build_environment(root, goos, goarch):
    return {**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0",
            "GOAMD64": "v1", "GOARM64": "v8.0", "GOEXPERIMENT": "", "GOWORK": "off",
            "GOFLAGS": f'"-modfile={root / ".build" / "go.mod"}" -mod=readonly -buildvcs=false'}


def notices(root, environment):
    modules = subprocess.check_output([
        "go", "list", "-deps", "-f",
        "{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}", "."
    ], cwd=root, env=environment, text=True)
    toolchain = json.loads(subprocess.check_output(
        ["go", "env", "-json", "GOROOT", "GOVERSION"], cwd=root, env=environment))
    license_path = Path(toolchain["GOROOT"]) / "LICENSE"
    if not license_path.is_file():
        # Nix omits GOROOT/LICENSE. Keep this official fallback pinned to the
        # reviewed toolchain: https://github.com/golang/go/blob/go1.26.7/LICENSE
        if toolchain["GOVERSION"] != "go1.26.7":
            raise ValueError("Go toolchain has no LICENSE; update the bundled license for this version")
        license_path = root / "scripts" / "GO_LICENSE.txt"
    go_license = license_path.read_text(encoding="utf-8")
    blocks = [f"\n=== Go standard library {toolchain['GOVERSION']} ===\nLICENSE\n{go_license}\n"]
    for entry in sorted(set(modules.splitlines())):
        if not entry:
            continue
        name, module_version, directory = entry.split("|", 2)
        if name == "github.com/Silo-Community/silo-plugin-tailscale":
            continue
        files = [p for p in Path(directory).iterdir() if p.is_file()
                 and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "COPYRIGHT"))]
        if not files:
            raise ValueError(f"Missing dependency license: {name}")
        blocks.append(f"\n=== {name} {module_version} ===\n")
        for path in sorted(files):
            blocks.append(path.name + "\n" + path.read_text(encoding="utf-8", errors="replace") + "\n")
    return "Third-party dependency notices\n" + "".join(blocks)


def write_archive(path, files):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, ARCHIVE_TIME)
            info.create_system = 3  # Preserve POSIX permissions on every build host.
            info.external_attr = (stat.S_IFREG | (0o755 if name == "plugin" else 0o644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, data, compresslevel=9)


def verify_binary(data, goos, goarch):
    if goos == "linux":
        machine = {"amd64": 62, "arm64": 183}[goarch]
        if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != machine:
            raise ValueError(f"Binary is not Linux {goarch}")
    elif goos == "darwin":
        if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe" or struct.unpack_from("<I", data, 4)[0] != 0x100000C:
            raise ValueError("Binary is not macOS arm64")
    else:
        raise ValueError(f"Unsupported binary platform: {goos}/{goarch}")


def verify_archive(path, version, goos, goarch):
    with zipfile.ZipFile(path) as bundle:
        if set(bundle.namelist()) != ARCHIVE_FILES or len(bundle.namelist()) != len(ARCHIVE_FILES):
            raise ValueError("Archive contains missing, unexpected, or duplicate files")
        for info in bundle.infolist():
            expected_mode = stat.S_IFREG | (0o755 if info.filename == "plugin" else 0o644)
            if info.date_time != ARCHIVE_TIME or info.external_attr >> 16 != expected_mode:
                raise ValueError(f"Incorrect archive metadata: {info.filename}")
            if not bundle.read(info).strip():
                raise ValueError(f"Empty archive entry: {info.filename}")
        binary = bundle.read("plugin")
        verify_binary(binary, goos, goarch)
        manifest = json.loads(bundle.read("manifest.json"))
        if manifest["version"] != version or manifest["checksum"] != hashlib.sha256(binary).hexdigest():
            raise ValueError("Archive manifest version or executable checksum does not match")
        if {tuple(sorted(item.items())) for item in manifest["supported_platforms"]} != {
                tuple(sorted({"os": os_name, "arch": architecture}.items())) for os_name, architecture in PLATFORMS}:
            raise ValueError("Manifest supported platforms do not match release targets")


def build_dist(root, version):
    validate_version(version)
    # Build in staging so a failed target never leaves a half-updated release.
    with tempfile.TemporaryDirectory(prefix="dist-", dir=root / ".build") as temporary:
        staging = Path(temporary)
        checksums = []
        for goos, goarch in PLATFORMS:
            platform = staging / f"{goos}-{goarch}"
            platform.mkdir()
            binary = platform / "plugin"
            environment = build_environment(root, goos, goarch)
            subprocess.run(["go", "build", "-trimpath", "-ldflags", f"-s -w -X main.version={version}",
                            "-o", str(binary), "."], cwd=root, env=environment, check=True)
            data = binary.read_bytes()
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            manifest["version"] = version
            manifest["checksum"] = hashlib.sha256(data).hexdigest()
            manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
            (platform / "manifest.json").write_bytes(manifest_bytes)
            archive = staging / f"silo-plugin-tailscale-{version}-{goos}-{goarch}.zip"
            write_archive(archive, {
                "plugin": data,
                "manifest.json": manifest_bytes,
                "LICENSE": (root / "LICENSE").read_bytes(),
                "LICENSE.tailscale": (root / ".build" / "tailscale" / "LICENSE").read_bytes(),
                "THIRD_PARTY_NOTICES.txt": notices(root, environment).encode(),
            })
            verify_archive(archive, version, goos, goarch)
            checksums.append(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}")
            print(archive.name, flush=True)
        (staging / "checksums.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
        dist = root / "dist"
        if dist.is_symlink():
            raise ValueError("Refusing a symlink at dist")
        if dist.exists():
            shutil.rmtree(dist)
        staging.rename(dist)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 scripts/dist.py VERSION")
    build_dist(Path(__file__).resolve().parents[1], sys.argv[1])
