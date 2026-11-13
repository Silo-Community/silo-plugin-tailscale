"""Regression tests for dependency integrity and installable release packages."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zipfile

import dist
import prepare_tailscale


def module_archive(path, files):
    digest = hashlib.sha256()
    with zipfile.ZipFile(path, "w") as bundle:
        for name, content in sorted(files.items()):
            full_name = f"tailscale.com@{prepare_tailscale.VERSION}/{name}"
            bundle.writestr(full_name, content)
            digest.update(f"{hashlib.sha256(content).hexdigest()}  {full_name}\n".encode())
    return "h1:" + base64.b64encode(digest.digest()).decode()


class PreparationTests(unittest.TestCase):
    def test_repeated_preparation_replaces_modified_and_extra_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "module.zip"
            checksum = module_archive(archive, {"original.go": b"verified source", "feature/acme/base.go": b"package acme"})
            (root / "go.mod").write_text("module example.test\n")
            (root / "go.sum").write_text(f"tailscale.com {prepare_tailscale.VERSION} {checksum}\n")
            (root / "scripts").mkdir()
            (root / "scripts/acme_state_test.go.txt").write_text("package acme\n")
            metadata = {"Version": prepare_tailscale.VERSION, "Sum": checksum, "Zip": str(archive)}
            with mock.patch.object(prepare_tailscale.subprocess, "check_output", return_value=json.dumps(metadata)), \
                    mock.patch.object(prepare_tailscale.subprocess, "run"), \
                    mock.patch.object(prepare_tailscale, "adapt_source"):
                prepare_tailscale.prepare(root)
                output = root / ".build/tailscale"
                (output / "original.go").write_text("locally modified")
                (output / "untracked.go").write_text("stale source")
                prepare_tailscale.prepare(root)
                self.assertEqual((output / "original.go").read_bytes(), b"verified source")
                self.assertFalse((output / "untracked.go").exists())
                self.assertEqual((root / "go.mod").read_text(), "module example.test\n")
                self.assertIn("replace tailscale.com => ./.build/tailscale", (root / ".build/go.mod").read_text())
                # A corrupted cache must fail before replacing the last valid source.
                module_archive(archive, {"original.go": b"tampered"})
                with self.assertRaisesRegex(ValueError, "checksum"):
                    prepare_tailscale.prepare(root)
                self.assertEqual((output / "original.go").read_bytes(), b"verified source")

    def test_missing_checksum_fails_before_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "go.sum").write_text("")
            with mock.patch.object(prepare_tailscale.subprocess, "check_output") as download:
                with self.assertRaisesRegex(ValueError, "committed checksum before download"):
                    prepare_tailscale.prepare(root)
                download.assert_not_called()

    def test_patch_rejects_missing_or_ambiguous_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for source in ("different", "before before"):
                (root / "source.go").write_text(source)
                with self.assertRaisesRegex(ValueError, "Upstream drift"):
                    prepare_tailscale.patch(root, "source.go", [("before", "after")])
                self.assertEqual((root / "source.go").read_text(), source)

    def test_archive_rejects_paths_outside_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(f"tailscale.com@{prepare_tailscale.VERSION}/../outside", b"bad")
            with self.assertRaisesRegex(ValueError, "Invalid module archive path"):
                prepare_tailscale.extract_verified_module(archive, Path(temporary) / "output", "irrelevant")


class DistributionTests(unittest.TestCase):
    def test_notices_include_go_license_when_toolchain_omits_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts/GO_LICENSE.txt").write_text("Go copyright and license")
            toolchain = {"GOROOT": str(root / "toolchain"), "GOVERSION": "go1.27.4"}
            with mock.patch.object(dist.subprocess, "check_output", side_effect=["", json.dumps(toolchain)]):
                self.assertIn("Go copyright and license", dist.notices(root, {}))
            toolchain["GOVERSION"] = "go1.99.0"
            with mock.patch.object(dist.subprocess, "check_output", side_effect=["", json.dumps(toolchain)]):
                with self.assertRaisesRegex(ValueError, "update the bundled license"):
                    dist.notices(root, {})

    def test_semantic_versions(self):
        for version in ("0.1.0", "1.20.300", "2.0.0-rc.1", "1.0.0-0", "1.0.0-beta-1"):
            dist.validate_version(version)
        for version in ("v1.0.0", "01.0.0", "1.0.0-01", "1.0.0-.", "1.0.0..", "../1.0.0", "1.0.0+local"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                dist.validate_version(version)

    def test_archive_is_reproducible_and_detects_incorrect_artifacts(self):
        binary = b"\x7fELF\x02\x01" + bytes(12) + struct.pack("<H", 62) + b"payload"
        manifest = {"version": "0.1.0", "checksum": hashlib.sha256(binary).hexdigest(),
                    "supported_platforms": [{"os": goos, "arch": goarch} for goos, goarch in dist.PLATFORMS]}
        files = {name: b"license notice" for name in dist.ARCHIVE_FILES}
        files.update({"plugin": binary, "manifest.json": json.dumps(manifest).encode()})
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / "first.zip", Path(temporary) / "second.zip"
            dist.write_archive(first, files)
            dist.write_archive(second, dict(reversed(list(files.items()))))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            dist.verify_archive(first, "0.1.0", "linux", "amd64")
            with self.assertRaisesRegex(ValueError, "not Linux arm64"):
                dist.verify_archive(first, "0.1.0", "linux", "arm64")
            with self.assertRaisesRegex(ValueError, "version or executable checksum"):
                dist.verify_archive(first, "0.2.0", "linux", "amd64")
            files["plugin"] += b"modified"
            dist.write_archive(second, files)
            with self.assertRaisesRegex(ValueError, "version or executable checksum"):
                dist.verify_archive(second, "0.1.0", "linux", "amd64")


if __name__ == "__main__":
    unittest.main()
