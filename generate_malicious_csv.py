#! /usr/bin/env python3
import argparse
import concurrent
import csv
import json
import os
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from tqdm import tqdm

ROOT = os.path.dirname(os.path.abspath(__file__))   # Directory of the current script
sys.path.insert(0, ROOT)  # ROOT must include the top-level package (e.g., amalfi)
from code.training.feature_extractor import (_guess_unpacked_root,
                                             _is_within_directory,
                                             _read_pkg_meta,
                                             _safe_extractall_tar,
                                             _safe_extractall_zip,
                                             _zip_is_encrypted)


def process_package_archive(archive_path: str):
    """
    Unpack + feature extraction, return a row dict (for scan_tarballs_to_csv to write to a unified large CSV).
    Return None on failure.
    """
    tarball_name = os.path.basename(archive_path)

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            lower = archive_path.lower()
            if lower.endswith((".tgz", ".tar.gz", ".tar")):
                with tarfile.open(archive_path, "r:*") as tar:
                    _safe_extractall_tar(tar, temp_dir)
            elif lower.endswith(".zip"):
                try:
                    with zipfile.ZipFile(archive_path, "r") as zf:
                        if _zip_is_encrypted(zf):
                            try:
                                _safe_extractall_zip(zf, temp_dir, password=b"infected")
                            except RuntimeError as re:
                                try:
                                    import pyzipper  # pip install pyzipper
                                    with pyzipper.AESZipFile(archive_path) as pzf:
                                        pzf.pwd = b"infected"
                                        for name in pzf.namelist():
                                            target = os.path.join(temp_dir, name)
                                            if not _is_within_directory(temp_dir, target):
                                                raise Exception(f"Blocked path traversal in zip: {name}")
                                        pzf.extractall(temp_dir)
                                except ImportError:
                                    raise RuntimeError(
                                        "Encrypted ZIP may be AES. Install 'pyzipper' to handle AES-encrypted zips."
                                    ) from re
                            except Exception:
                                raise
                        else:
                            _safe_extractall_zip(zf, temp_dir, password=None)
                except Exception as e:
                    print(f"[SKIP] Failed to unpack (zip) {os.path.basename(archive_path)}: {e}")
                    return None
            else:
                print(f"[SKIP] Unsupported archive type: {archive_path}")
                return None

            unpacked_path = _guess_unpacked_root(temp_dir)
        except Exception as e:
            print(f"[SKIP] Failed to unpack {tarball_name}: {e}")
            return None

        pkg_name, pkg_ver = _read_pkg_meta(unpacked_path)

        row = {
            "package_name": pkg_name or Path(archive_path).stem.replace(".tgz", "").replace(".tar", "").replace(".zip", ""),
            "package_version": pkg_ver or "",
        }

        return row

def extract_name_version_from_archive(archive_path: str):
    """
    Unpack and read package.json from .tgz/.tar(.gz)/.zip archives, return (name, version).
    - .zip supports password 'infected'; if AES-encrypted, try pyzipper.
    - Use the same secure unpacking strategy as process_package_archive.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        lower = archive_path.lower()

        # 1) Unpack (maintain consistent branching and fallback strategy with process_package_archive above)
        try:
            if lower.endswith((".tgz", ".tar.gz", ".tar")):
                with tarfile.open(archive_path, "r:*") as tar:
                    _safe_extractall_tar(tar, tmpdir)

            elif lower.endswith(".zip"):
                try:
                    with zipfile.ZipFile(archive_path, "r") as zf:
                        if _zip_is_encrypted(zf):
                            # Try traditional ZipCrypto first
                            try:
                                _safe_extractall_zip(zf, tmpdir, password=b"infected")
                            except RuntimeError as re:
                                # Might be AES, fallback to pyzipper
                                try:
                                    import pyzipper  # pip install pyzipper
                                    with pyzipper.AESZipFile(archive_path) as pzf:
                                        pzf.pwd = b"infected"
                                        for name in pzf.namelist():
                                            target = os.path.join(tmpdir, name)
                                            if not _is_within_directory(tmpdir, target):
                                                raise Exception(f"Blocked path traversal in zip: {name}")
                                        pzf.extractall(tmpdir)
                                except ImportError:
                                    raise RuntimeError(
                                        "Encrypted ZIP may be AES. Install 'pyzipper' to handle AES-encrypted zips."
                                    ) from re
                        else:
                            _safe_extractall_zip(zf, tmpdir, password=None)
                except Exception as e:
                    print(f"[WARN] Failed to unpack (zip) {os.path.basename(archive_path)}: {e}")
                    return None, None

            else:
                print(f"[WARN] Unsupported archive type: {archive_path}")
                return None, None

        except Exception as e:
            print(f"[WARN] Failed to unpack {os.path.basename(archive_path)}: {e}")
            return None, None

        # 2) Locate package root directory (same as the above process)
        try:
            pkg_root = _guess_unpacked_root(tmpdir)
        except Exception:
            # Fallback strategy: common npm top-level package/ directory
            entries = [e for e in os.listdir(tmpdir) if not e.startswith(".")]
            if len(entries) == 1 and os.path.isdir(os.path.join(tmpdir, entries[0])):
                pkg_root = os.path.join(tmpdir, entries[0])
            else:
                pkg_root = tmpdir

        # 3) Read package.json
        # Common path: pkg_root/package.json; if not exists, do a shallow traversal as fallback
        candidates = [os.path.join(pkg_root, "package.json")]
        if not os.path.exists(candidates[0]):
            for root, _, files in os.walk(pkg_root):
                if "package.json" in files:
                    candidates.append(os.path.join(root, "package.json"))
                    break

        for pj in candidates:
            if os.path.exists(pj):
                try:
                    with open(pj, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    return data.get("name"), data.get("version")
                except Exception as e:
                    print(f"[WARN] Failed to read package.json in {archive_path}: {e}")
                    return None, None

        return None, None

def scan_tarballs_to_csv(tarballs_dir: str, out_csv: str, max_workers: int = None):
    """
    Recursively scan all .tgz/.tar.gz/.tar/.zip in the directory, process in parallel, and write results to CSV in real-time.
    """

    header = ["package_name","package_version"]

    write_header = not os.path.exists(out_csv)

    archive_paths = []
    for root, _, files in os.walk(tarballs_dir):
        for fn in files:
            lower = fn.lower()
            if lower.endswith((".tgz", ".tar.gz", ".tar", ".zip")):
                archive_paths.append(os.path.join(root, fn))

    print(f"Found {len(archive_paths)} archives under {tarballs_dir}")

    with open(out_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)

        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_package_archive, path): path for path in archive_paths}

            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Processing archives"):
                path = futures[future]
                try:
                    row = future.result()
                    if not row:
                        continue

                    for col in header:
                        if col not in row:
                            row[col] = ""

                    writer.writerow(row)   # Write in real-time
                except Exception as e:
                    print(f"\n[ERROR] {path}: {e}")

    print(f"✅ Done. Results written to {out_csv}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate malicious.csv from malicious dataset (.tgz files)")
    parser.add_argument("malicious_dir", help="Directory of malicious dataset (recursive search)")
    parser.add_argument("-o", "--output", required=True, help="Output malicious.csv path")
    args = parser.parse_args()

    scan_tarballs_to_csv(args.malicious_dir, args.output)
