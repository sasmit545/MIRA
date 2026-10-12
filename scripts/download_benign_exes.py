#!/usr/bin/env python3
"""
Download a small benign-Windows-EXE starter corpus for MIRA testing.

Downloads official Windows Sysinternals utilities from Microsoft's official
Sysinternals ZIP packages. Windows inbox tools (notepad.exe, whoami.exe, etc.)
are NOT downloaded here because they are already part of Windows; copy them
from a trusted Windows installation instead.

Usage:
    python download_benign_exes.py
    python download_benign_exes.py --out-dir benign_exes
    python download_benign_exes.py --include-sysinternals

Safety:
- Downloads only from Microsoft-owned download URLs.
- Does not execute downloaded files.
- Extracts only explicitly named .exe files.
- Computes SHA-256 hashes and writes a CSV manifest.
- A valid signature or official source is helpful provenance, not an absolute
  guarantee that a file is safe. Verify files before using them as labels.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable

# Official Microsoft Sysinternals packages. The downloaded ZIP is held in
# memory and only the explicitly named executable is written to disk.
SYSINTERNALS = {
    "strings.exe": {
        "url": "https://download.sysinternals.com/files/Strings.zip",
        "member": "strings.exe",
        "description": "Searches executable/binary files for strings",
    },
    "sigcheck.exe": {
        "url": "https://download.sysinternals.com/files/Sigcheck.zip",
        "member": "sigcheck.exe",
        "description": "Displays file version and signature information",
    },
    "pslist.exe": {
        "url": "https://download.sysinternals.com/files/PSTools.zip",
        "member": "pslist.exe",
        "description": "Lists processes and threads",
    },
}

# Windows inbox utilities. These are not hosted as standalone downloads here.
WINDOWS_INBOX_EXES = [
    "notepad.exe",
    "whoami.exe",
    "where.exe",
    "hostname.exe",
    "findstr.exe",
    "sort.exe",
    "fc.exe",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_bytes(url: str, timeout: int = 45) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "MIRA-Benign-EXE-Dataset/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP status {response.status} for {url}")
        data = response.read()
    if not data:
        raise RuntimeError(f"Empty download from {url}")
    return data


def safe_extract_named_exe(zip_bytes: bytes, member_name: str, destination: Path) -> None:
    """Extract one exact basename only; do not extract arbitrary ZIP paths."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        candidates = [
            info for info in archive.infolist()
            if not info.is_dir() and Path(info.filename.replace("\\", "/")).name.lower()
            == member_name.lower()
        ]
        if len(candidates) != 1:
            raise RuntimeError(
                f"Expected exactly one {member_name} in ZIP; found {len(candidates)}"
            )
        info = candidates[0]
        if info.file_size <= 0 or info.file_size > 100 * 1024 * 1024:
            raise RuntimeError(
                f"Unexpected size for {member_name}: {info.file_size} bytes"
            )
        # Read member bytes directly; no ZIP path is written to disk.
        data = archive.read(info)
        if not data.startswith(b"MZ"):
            raise RuntimeError(f"{member_name} does not have a PE MZ header")
        destination.write_bytes(data)


def copy_windows_inbox_files(windows_root: Path, out_dir: Path) -> list[dict[str, str]]:
    rows = []
    search_roots = [
        windows_root / "System32",
        windows_root / "SysWOW64",
    ]
    for name in WINDOWS_INBOX_EXES:
        matches = []
        for root in search_roots:
            candidate = root / name
            if candidate.is_file():
                matches.append(candidate)
        if not matches:
            print(f"[SKIP] {name}: not found under {windows_root}\\System32 or SysWOW64")
            continue
        # Prefer System32 when available.
        source = next((p for p in matches if p.parent.name.lower() == "system32"), matches[0])
        destination = out_dir / name
        if destination.exists():
            print(f"[SKIP] {name}: output already exists at {destination}")
            continue
        destination.write_bytes(source.read_bytes())
        rows.append({
            "filename": name,
            "source": str(source),
            "sha256": sha256_file(destination),
            "size_bytes": str(destination.stat().st_size),
            "label": "benign_candidate",
            "notes": "Copied from local Windows installation; verify provenance/signature",
        })
        print(f"[OK] copied {name} ({destination.stat().st_size:,} bytes)")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir", default="benign_exes",
        help="Output directory (default: ./benign_exes)",
    )
    parser.add_argument(
        "--windows-root", default=os.environ.get("WINDIR", r"C:\Windows"),
        help=r"Windows directory to copy inbox EXEs from (default: %%WINDIR%%)",
    )
    parser.add_argument(
        "--include-sysinternals", action="store_true",
        help="Download strings.exe, sigcheck.exe and pslist.exe from Microsoft",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []

    # Copy native Windows files when run on Windows.
    windows_root = Path(args.windows_root)
    if windows_root.exists() and (windows_root / "System32").is_dir():
        rows.extend(copy_windows_inbox_files(windows_root, out_dir))
    else:
        print("[INFO] Windows inbox EXEs not copied (not running against a Windows directory).")
        print("       Run this script on Windows, or pass --windows-root C:\\Windows.")

    if args.include_sysinternals:
        for filename, item in SYSINTERNALS.items():
            destination = out_dir / filename
            if destination.exists():
                print(f"[SKIP] {filename}: already exists")
                continue
            try:
                print(f"[DOWNLOAD] {filename} from official Microsoft Sysinternals")
                data = download_bytes(item["url"])
                safe_extract_named_exe(data, item["member"], destination)
                rows.append({
                    "filename": filename,
                    "source": item["url"],
                    "sha256": sha256_file(destination),
                    "size_bytes": str(destination.stat().st_size),
                    "label": "benign_candidate",
                    "notes": item["description"] + "; verify signature/hash before labeling",
                })
                print(f"[OK] downloaded {filename} ({destination.stat().st_size:,} bytes)")
            except (urllib.error.URLError, TimeoutError, zipfile.BadZipFile, RuntimeError, OSError) as exc:
                print(f"[ERROR] {filename}: {exc}", file=sys.stderr)
                if destination.exists():
                    destination.unlink()
    else:
        print("[INFO] Skipping Sysinternals downloads. Use --include-sysinternals to include them.")

    manifest = out_dir / "manifest.csv"
    existing_rows: list[dict[str, str]] = []
    if manifest.exists():
        try:
            with manifest.open("r", newline="", encoding="utf-8") as f:
                existing_rows = list(csv.DictReader(f))
        except OSError:
            pass

    by_filename = {row.get("filename"): row for row in existing_rows if row.get("filename")}
    for row in rows:
        by_filename[row["filename"]] = row

    fields = ["filename", "source", "sha256", "size_bytes", "label", "notes"]
    with manifest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for filename in sorted(by_filename):
            writer.writerow({field: by_filename[filename].get(field, "") for field in fields})

    print(f"\nManifest written: {manifest}")
    print("Files are labeled 'benign_candidate' deliberately; verify before treating them as ground truth.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
