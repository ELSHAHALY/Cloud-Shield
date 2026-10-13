#!/usr/bin/env python3
"""Build the SOAR Lambda zip deterministically (make package-soar).

Same source -> byte-identical zip on any OS, so the artifact hash is stable:
sorted entries, fixed 1980-01-01 timestamps, 0644 permissions, LF line
endings, and no tests or caches. boto3 is not vendored: the Lambda runtime
provides it. Prints the SHA-256 (hex) and the base64 form Lambda reports as
CodeSha256.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import zipfile
from pathlib import Path

PACKAGES = ("core", "safety_guard", "playbooks")
_EPOCH = (1980, 1, 1, 0, 0, 0)


def source_files(src: Path) -> list[Path]:
    files = []
    for package in PACKAGES:
        root = src / package
        if not (root / "__init__.py").is_file():
            raise SystemExit(f"missing package {root}")
        files.extend(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)
    return sorted(files, key=lambda p: p.relative_to(src).as_posix())


def build(src: Path, out: Path) -> str:
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w") as archive:
        for path in source_files(src):
            info = zipfile.ZipInfo(path.relative_to(src).as_posix(), date_time=_EPOCH)
            info.external_attr = 0o100644 << 16
            info.create_system = 3  # Unix, so the permissions above are honoured
            info.compress_type = zipfile.ZIP_DEFLATED
            data = path.read_bytes().replace(b"\r\n", b"\n")  # Windows checkouts
            archive.writestr(info, data, compresslevel=9)
    return hashlib.sha256(out.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--src", type=Path, default=repo / "soar")
    parser.add_argument("--out", type=Path, default=repo / "build" / "soar-playbooks.zip")
    args = parser.parse_args(argv)

    digest = build(args.src, args.out)
    print(f"{args.out}")
    print(f"sha256      {digest}")
    print(f"CodeSha256  {base64.b64encode(bytes.fromhex(digest)).decode()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
