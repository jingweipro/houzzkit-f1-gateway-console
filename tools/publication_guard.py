#!/usr/bin/env python3
"""Fail-closed publication checks. Findings contain locations, NEVER matched secrets."""
import argparse
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_TEXT_BYTES = 8 * 1024 * 1024
SECRET_PATTERNS = {
    "private-key-header": re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "provider-token": re.compile(
        rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
        rb"sk-proj-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|"
        rb"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
        rb"AIza[0-9A-Za-z_-]{30,})"
    ),
    "credential-assignment": re.compile(
        rb"(?i)(?:password|passwd|client_secret|access_token|api[_-]?key|auth[_-]?token)"
        rb"\s*[:=]\s*['\"]?([A-Za-z0-9/+_=-]{24,})"
    ),
    "url-credential": re.compile(
        rb"(?i)https?://[^\s\"'<>]{3,500}[?&](?:token|key|secret|password|"
        rb"auth|api_key)=([^&\s\"'<>]{6,300})"
    ),
    "local-personal-path": re.compile(rb"/Users/[A-Za-z0-9._-]+/"),
}
PLACEHOLDERS = (
    b"fake", b"test", b"sample", b"dummy", b"redacted", b"placeholder",
    b"example", b"unit-marker", b"supersecret", b"xxxxx",
)
DENIED_BASENAMES = {
    ".env", "auth.json", "initial-password.txt", "subscriptions.json",
    "id_rsa", "id_ed25519", "credentials.json", "service-account.json",
    "kubeconfig", "token.txt", ".npmrc", ".pypirc",
}
DENIED_SUFFIXES = (".p12", ".pfx", ".key", ".pem", ".hdp")
IGNORED_PERSONAL_PATHS = (b"/Users/example/", b"/Users/runner/", b"/Users/demo/")
PNG_PRIVATE_CHUNKS = (b"tEXt", b"iTXt", b"zTXt", b"eXIf")


def ignored_placeholder(matched):
    value = matched.lower()
    if any(v in value for v in PLACEHOLDERS):
        return True
    # A prompt-only input field, not an actual credential.
    return value.endswith(b"?token=...") or value.endswith(b"?key=...")


def inspect_bytes(name, data):
    """Return (rule, line) tuples, never raw values."""
    flags = []
    lower = Path(name).name.lower()
    if lower in DENIED_BASENAMES or lower.startswith("backup-") or lower.endswith(DENIED_SUFFIXES):
        flags.append(("sensitive-filename", 0))
    if len(data) > MAX_TEXT_BYTES:
        # Publishing an uninspectable non-image blob is not a safe default.
        if Path(name).suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
            flags.append(("oversized-unscanned", 0))
        return flags
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        pos = 8
        while pos + 12 <= len(data):
            size = int.from_bytes(data[pos:pos + 4], "big")
            typ = data[pos + 4:pos + 8]
            if typ in PNG_PRIVATE_CHUNKS:
                flags.append(("png-metadata", 0))
            if size > MAX_TEXT_BYTES or pos + size + 12 > len(data):
                flags.append(("invalid-png", 0))
                break
            pos += size + 12
            if typ == b"IEND":
                break
        return flags
    if b"\x00" in data[:1024]:
        return flags  # Other binary formats need a separate binary/image review.
    for label, regex in SECRET_PATTERNS.items():
        for match in regex.finditer(data):
            if label == "local-personal-path" and match.group() in IGNORED_PERSONAL_PATHS:
                continue
            if label in ("url-credential", "credential-assignment") and ignored_placeholder(match.group()):
                continue
            line = data.count(b"\n", 0, match.start()) + 1
            flags.append((label, line))
    return flags


def command(*args, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, capture_output=True, check=True)
    return result.stdout


def inspect_worktree(root=ROOT):
    tracked = command("git", "ls-files", "-z", cwd=root).split(b"\x00")
    for raw in tracked:
        if not raw:
            continue
        rel = raw.decode("utf-8", "replace")
        path = root / rel
        if not path.is_file():
            yield rel, "missing-tracked-file", 0
            continue
        for label, line in inspect_bytes(rel, path.read_bytes()):
            yield rel, label, line


def inspect_git_history(root=ROOT):
    """All reachable blobs on the checked-out ref; requires fetch-depth: 0 in CI."""
    records = command("git", "rev-list", "--objects", "--all", cwd=root).decode("utf-8", "replace")
    seen = set()
    for record in records.splitlines():
        sha, _, path = record.partition(" ")
        if sha in seen or not path:
            continue
        seen.add(sha)
        if command("git", "cat-file", "-t", sha, cwd=root).strip() != b"blob":
            continue
        size = int(command("git", "cat-file", "-s", sha, cwd=root))
        if size > MAX_TEXT_BYTES:
            yield "history:" + sha[:12] + ":" + path, "oversized-historical-blob", 0
            continue
        data = command("git", "cat-file", "blob", sha, cwd=root)
        for label, line in inspect_bytes(path, data):
            yield "history:" + sha[:12] + ":" + path, label, line
    emails = command("git", "log", "--all", "--format=%ae%n%ce", cwd=root).decode("utf-8", "replace")
    for i, email in enumerate(emails.splitlines(), 1):
        email = email.strip().lower()
        if email and "@" in email and not (
            email.endswith("@localhost") or email.endswith("@github.com")
            or email.endswith("@users.noreply.github.com")
        ):
            yield "git-history:commit-identity", "personal-author-email", i


def inspect_extra_dir(directory):
    root = Path(directory)
    if not root.is_dir():
        yield str(root), "missing-package-directory", 0
        return
    for path in root.rglob("*"):
        if path.is_symlink():
            yield str(path), "symlink-in-package", 0
        elif path.is_file():
            for label, line in inspect_bytes(str(path.relative_to(root)), path.read_bytes()):
                yield str(path), label, line


def inspect_image_archive(filename):
    """Scan Docker's OCI or legacy docker-save tar before registry push."""
    with tarfile.open(filename, mode="r:*") as outer:
        for item in outer:
            if not item.isfile():
                continue
            normalized = item.name.lstrip("./")
            # OCI index/config/manifests and classic Docker config.
            if normalized in ("index.json", "manifest.json") or normalized.endswith(".json"):
                if item.size <= MAX_TEXT_BYTES:
                    data = outer.extractfile(item).read()
                    for label, line in inspect_bytes("image:" + normalized, data):
                        yield "image:" + normalized, label, line
            potential_layer = (
                normalized.endswith("/layer.tar")
                or (normalized.startswith("blobs/sha256/"))
            )
            if not potential_layer:
                continue
            stream = outer.extractfile(item)
            try:
                inner = tarfile.open(fileobj=stream, mode="r|*")
            except tarfile.TarError:
                continue  # OCI metadata blob, not an image layer
            with inner:
                for inner_item in inner:
                    name = inner_item.name.lstrip("./")
                    if not inner_item.isfile():
                        continue
                    basename = Path(name).name.lower()
                    sensitive_filename = (
                        basename in DENIED_BASENAMES or basename.startswith("backup-")
                        or basename.endswith(DENIED_SUFFIXES)
                    )
                    app_file = name.startswith(("opt/console/", "opt/f1-console/", "app/", "srv/", "workspace/", "data/", "home/"))
                    if not (sensitive_filename or app_file):
                        continue
                    if inner_item.size > MAX_TEXT_BYTES:
                        yield "image:" + name, "oversized-unscanned", 0
                        continue
                    data = inner.extractfile(inner_item).read()
                    for label, line in inspect_bytes("image:" + name, data):
                        yield "image:" + name, label, line


def inspect_package_archive(filename):
    """Reject private or uninspectable entries in proposed HOS/ZIP assets."""
    with zipfile.ZipFile(filename) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.file_size > MAX_TEXT_BYTES:
                yield "package:" + info.filename, "oversized-unscanned", 0
                continue
            for label, line in inspect_bytes(info.filename, archive.read(info)):
                yield "package:" + info.filename, label, line


def main():
    parser = argparse.ArgumentParser(description="Sanitized publication gate (no raw secrets in logs)")
    parser.add_argument("--history", action="store_true", help="check reachable git blobs and author emails")
    parser.add_argument("--extra-dir", action="append", default=[], help="directory to check, e.g. HOS app")
    parser.add_argument("--image-tar", help="Docker save tar of ARM64 candidate, before publishing")
    parser.add_argument("--package-zip", help="HDP/ZIP to inspect before publishing")
    options = parser.parse_args()
    failures = list(inspect_worktree())
    if options.history:
        failures += list(inspect_git_history())
    for root in options.extra_dir:
        failures += list(inspect_extra_dir(root))
    if options.image_tar:
        failures += list(inspect_image_archive(options.image_tar))
    if options.package_zip:
        failures += list(inspect_package_archive(options.package_zip))
    # A failed gate never prints matched data, source lines, URLs, or secret values.
    for path, category, line in failures[:100]:
        display_path = path.replace("\n", "_").replace("\r", "_")[:180]
        print("PUBLICATION_BLOCKED", display_path, "line", line, "rule", category)
    if len(failures) > 100:
        print("ADDITIONAL_FINDINGS", len(failures) - 100)
    if failures:
        print("PUBLICATION_GUARD=FAIL count=", len(failures))
        return 1
    print("PUBLICATION_GUARD=PASS checked_worktree=yes history=", options.history,
          "image=", bool(options.image_tar), "package=", bool(options.package_zip))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print("PUBLICATION_GUARD=ERROR", type(exc).__name__)
        sys.exit(2)
