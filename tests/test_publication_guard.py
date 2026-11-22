"""Offline regression tests for publication preflight; never embed real credentials."""
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import publication_guard as guard


def synthetic_credential():
    # Construct at runtime so test source itself never contains a key-shaped value.
    return "gh" + "p_" + ("Z" * 36)


class PublicationSafety(unittest.TestCase):
    def test_safe_placeholder_and_rfc5737_examples(self):
        raw = b"https://example.org/sub?token=fake-secret\n" + b"IP=198.51.100.23\n"
        self.assertFalse(guard.inspect_bytes("tests/fixture.txt", raw))

    def test_detects_token_without_returning_secret_value(self):
        secret = synthetic_credential().encode()
        found = guard.inspect_bytes("app/config.py", b"token=" + secret)
        self.assertTrue(any(label == "provider-token" for label, _ in found))
        self.assertNotIn(secret.decode(), str(found))

    def test_deny_private_runtime_files(self):
        for name in ("auth.json", "subscriptions.json", "backup-20261122.yaml",
                     "id_ed25519", ".env", "INITIAL-PASSWORD.txt", "secret.p12"):
            with self.subTest(name=name):
                self.assertIn(("sensitive-filename", 0), guard.inspect_bytes("config/" + name, b""))

    def test_private_key_marker_and_personal_path(self):
        pem = ("-----BEGIN " + "OPENSSH PRIVATE KEY-----").encode()
        self.assertTrue(guard.inspect_bytes("code/sample.txt", pem))
        self.assertFalse(guard.inspect_bytes("README.md", b"/Users/example/project"))
        self.assertTrue(guard.inspect_bytes("README.md", b"/Users/" + b"privateowner/project"))

    def test_binary_and_png_metadata_gate(self):
        blob = b"\x89PNG\r\n\x1a\n" + (4).to_bytes(4, "big") + b"tEXt" + b"demo" + b"CRC0"
        self.assertIn(("png-metadata", 0), guard.inspect_bytes("app/icon.png", blob))

    def test_history_contains_deleted_secret(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "config", "user.name", "Demo"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "demo@localhost"], cwd=root, check=True)
            file = root / "fixture.txt"
            file.write_text("secret=" + synthetic_credential())
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "private initial commit"], cwd=root, check=True)
            file.unlink()
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "delete bad file"], cwd=root, check=True)
            self.assertTrue(any(rule == "provider-token" for _, rule, _ in guard.inspect_git_history(root)))

    def test_public_ca_bundle_is_allowed_but_private_key_is_not(self):
        path = "usr/local/lib/python3.13/site-packages/pip/_vendor/certifi/cacert.pem"

        def scan_layer(payload):
            inner_data = io.BytesIO()
            with tarfile.open(fileobj=inner_data, mode="w") as inner:
                item = tarfile.TarInfo(path)
                item.size = len(payload)
                inner.addfile(item, io.BytesIO(payload))
            with tempfile.TemporaryDirectory() as td:
                image_tar = Path(td) / "image.tar"
                with tarfile.open(image_tar, mode="w") as outer:
                    item = tarfile.TarInfo("blobs/sha256/" + "c" * 64)
                    item.size = len(inner_data.getvalue())
                    outer.addfile(item, io.BytesIO(inner_data.getvalue()))
                return list(guard.inspect_image_archive(image_tar))

        cert = b"-----BEGIN CERTIFICATE-----\nFAKEPUBLICCABUNDLE\n-----END CERTIFICATE-----\n"
        self.assertFalse(scan_layer(cert))
        private = b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\nFAKEPRIVATE\n"
        self.assertTrue(scan_layer(private))

    def test_image_layer_scans_app_and_redacts_result(self):
        key = synthetic_credential().encode()
        content = b'ACCESS_TOKEN="' + key + b'"\n'
        inner_data = io.BytesIO()
        with tarfile.open(fileobj=inner_data, mode="w") as t:
            entry = tarfile.TarInfo("opt/console/app.py")
            entry.size = len(content)
            t.addfile(entry, io.BytesIO(content))
        layer = inner_data.getvalue()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "image.tar"
            with tarfile.open(out, mode="w") as t:
                item = tarfile.TarInfo("blobs/sha256/" + "a" * 64)
                item.size = len(layer)
                t.addfile(item, io.BytesIO(layer))
            findings = list(guard.inspect_image_archive(out))
            self.assertTrue(any(rule == "provider-token" for _, rule, _ in findings))
            self.assertNotIn(key.decode(), str(findings))


if __name__ == "__main__":
    unittest.main()
