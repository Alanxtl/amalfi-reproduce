import argparse
import concurrent.futures
import csv
import json
import os
import re
import tarfile
import tempfile
import zipfile
from pathlib import Path

import numpy as np
import tree_sitter_javascript as jsts
import tree_sitter_typescript as tsts
from scipy.stats import entropy
from tqdm import tqdm  # pip install tqdm
from tree_sitter import Language, Parser

# --- Language Initialization ---
JS_LANGUAGE = Language(jsts.language()) 
TS_LANGUAGE = Language(tsts.language_typescript())

# --- Feature Queries ---
ALL_QUERIES = {
    "fs_access": {
        "javascript": r"""
        [
          (call_expression
            function: (identifier) @id
            arguments: (arguments (string (string_fragment) @mod))
            (#eq? @id "require")
            (#match? @mod "^(fs|fs/promises)$")
          )
          (import_statement
            source: (string) @src
            (#match? @src "^['\"](fs|fs/promises)['\"]$")
          )
          [
            (call_expression
              function: (import)
              arguments: (arguments (string (string_fragment) @dmod))
              (#match? @dmod "^(fs|fs/promises)$")
            )
            (call_expression
              function: (identifier) @__dyn_import_id
              arguments: (arguments (string (string_fragment) @dmod2))
              (#eq? @__dyn_import_id "import")
              (#match? @dmod2 "^(fs|fs/promises)$")
            )
          ]
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#match? @obj "^(fs|fsPromises|FileSystem|fsExtra)$")
            (#match? @prop "^(read(File|FileSync|dir)|write(File|FileSync)|open|exists|create(Read|Write)Stream)$")
          )
        ]
        """,
        "typescript": r"""
        [
          (call_expression
            function: (identifier) @id
            arguments: (arguments (string (string_fragment) @mod))
            (#eq? @id "require")
            (#match? @mod "^(fs|fs/promises)$")
          )
          (import_statement
            source: (string) @src
            (#match? @src "^['\"](fs|fs/promises)['\"]$")
          )
          [
            (call_expression
              function: (import)
              arguments: (arguments (string (string_fragment) @dmod))
              (#match? @dmod "^(fs|fs/promises)$")
            )
            (call_expression
              function: (identifier) @__dyn_import_id
              arguments: (arguments (string (string_fragment) @dmod2))
              (#eq? @__dyn_import_id "import")
              (#match? @dmod2 "^(fs|fs/promises)$")
            )
          ]
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#match? @obj "^(fs|fsPromises|FileSystem|fsExtra)$")
            (#match? @prop "^(read(File|FileSync|dir)|write(File|FileSync)|open|exists|create(Read|Write)Stream)$")
          )
        ]
        """
    },

    "process_creation": {
        "javascript": r"""
        [
          (call_expression
            function: (identifier) @id
            arguments: (arguments (string (string_fragment) @mod))
            (#eq? @id "require")
            (#match? @mod "^(child_process|execa|shelljs)$")
          )
          (import_statement
            source: (string) @src
            (#match? @src "^['\"](child_process|execa|shelljs)['\"]$")
          )
          [
            (call_expression
              function: (import)
              arguments: (arguments (string (string_fragment) @dmod))
              (#match? @dmod "^(child_process|execa|shelljs)$")
            )
            (call_expression
              function: (identifier) @__dyn_import_id
              arguments: (arguments (string (string_fragment) @dmod2))
              (#eq? @__dyn_import_id "import")
              (#match? @dmod2 "^(child_process|execa|shelljs)$")
            )
          ]
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#match? @prop "^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$")
          )
        ]
        """,
        "typescript": r"""
        [
          (call_expression
            function: (identifier) @id
            arguments: (arguments (string (string_fragment) @mod))
            (#eq? @id "require")
            (#match? @mod "^(child_process|execa|shelljs)$")
          )
          (import_statement
            source: (string) @src
            (#match? @src "^['\"](child_process|execa|shelljs)['\"]$")
          )
          [
            (call_expression
              function: (import)
              arguments: (arguments (string (string_fragment) @dmod))
              (#match? @dmod "^(child_process|execa|shelljs)$")
            )
            (call_expression
              function: (identifier) @__dyn_import_id
              arguments: (arguments (string (string_fragment) @dmod2))
              (#eq? @__dyn_import_id "import")
              (#match? @dmod2 "^(child_process|execa|shelljs)$")
            )
          ]
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#match? @prop "^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$")
          )
        ]
        """
    },

    "network_access": {
        "javascript": r"""
        [
          (call_expression
            function: (identifier) @id
            arguments: (arguments (string (string_fragment) @mod))
            (#eq? @id "require")
            (#match? @mod "^(http|https|net|dgram|tls|ws|axios|node-fetch|undici)$")
          )
          (import_statement
            source: (string) @src
            (#match? @src "^['\"](http|https|net|dgram|tls|ws|axios|node-fetch|undici)['\"]$")
          )
          [
            (call_expression
              function: (import)
              arguments: (arguments (string (string_fragment) @dmod))
              (#match? @dmod "^(http|https|net|dgram|tls|ws|axios|node-fetch|undici)$")
            )
            (call_expression
              function: (identifier) @__dyn_import_id
              arguments: (arguments (string (string_fragment) @dmod2))
              (#eq? @__dyn_import_id "import")
              (#match? @dmod2 "^(http|https|net|dgram|tls|ws|axios|node-fetch|undici)$")
            )
          ]
          (call_expression
            function: (identifier) @func
            (#match? @func "^(fetch|axios)$")
          )
          (new_expression
            constructor: (identifier) @ctor
            (#eq? @ctor "WebSocket")
          )
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#match? @obj "^(http|https|net|dgram|tls)$")
          )
        ]
        """,
        "typescript": r"""
        [
          (call_expression
            function: (identifier) @id
            arguments: (arguments (string (string_fragment) @mod))
            (#eq? @id "require")
            (#match? @mod "^(http|https|net|dgram|tls|ws|axios|node-fetch|undici)$")
          )
          (import_statement
            source: (string) @src
            (#match? @src "^['\"](http|https|net|dgram|tls|ws|axios|node-fetch|undici)['\"]$")
          )
          [
            (call_expression
              function: (import)
              arguments: (arguments (string (string_fragment) @dmod))
              (#match? @dmod "^(http|https|net|dgram|tls|ws|axios|node-fetch|undici)$")
            )
            (call_expression
              function: (identifier) @__dyn_import_id
              arguments: (arguments (string (string_fragment) @dmod2))
              (#eq? @__dyn_import_id "import")
              (#match? @dmod2 "^(http|https|net|dgram|tls|ws|axios|node-fetch|undici)$")
            )
          ]
          (call_expression
            function: (identifier) @func
            (#match? @func "^(fetch|axios)$")
          )
          (new_expression
            constructor: (identifier) @ctor
            (#eq? @ctor "WebSocket")
          )
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#match? @obj "^(http|https|net|dgram|tls)$")
          )
        ]
        """
    },

    "crypto_api": {
        "javascript": r"""
        [
          (call_expression
            function: (identifier) @id
            arguments: (arguments (string (string_fragment) @mod))
            (#eq? @id "require")
            (#match? @mod "^crypto$")
          )
          (import_statement
            source: (string) @src
            (#match? @src "^['\"]crypto['\"]$")
          )
          [
            (call_expression
              function: (import)
              arguments: (arguments (string (string_fragment) @dmod))
              (#match? @dmod "^crypto$")
            )
            (call_expression
              function: (identifier) @__dyn_import_id
              arguments: (arguments (string (string_fragment) @dmod2))
              (#eq? @__dyn_import_id "import")
              (#match? @dmod2 "^crypto$")
            )
          ]
          (member_expression
            object: (member_expression
              object: (identifier) @g
              property: (property_identifier) @p1)
            property: (property_identifier) @p2
            (#match? @g "^(globalThis|self|window)$")
            (#eq? @p1 "crypto")
            (#eq? @p2 "subtle")
          )
        ]
        """,
        "typescript": r"""
        [
          (call_expression
            function: (identifier) @id
            arguments: (arguments (string (string_fragment) @mod))
            (#eq? @id "require")
            (#match? @mod "^crypto$")
          )
          (import_statement
            source: (string) @src
            (#match? @src "^['\"]crypto['\"]$")
          )
          [
            (call_expression
              function: (import)
              arguments: (arguments (string (string_fragment) @dmod))
              (#match? @dmod "^crypto$")
            )
            (call_expression
              function: (identifier) @__dyn_import_id
              arguments: (arguments (string (string_fragment) @dmod2))
              (#eq? @__dyn_import_id "import")
              (#match? @dmod2 "^crypto$")
            )
          ]
          (member_expression
            object: (member_expression
              object: (identifier) @g
              property: (property_identifier) @p1)
            property: (property_identifier) @p2
            (#match? @g "^(globalThis|self|window)$")
            (#eq? @p1 "crypto")
            (#eq? @p2 "subtle")
          )
        ]
        """
    },

    "data_encoding": {
        "javascript": r"""
        [
          (call_expression
            function: (identifier) @func
            (#match? @func "^(btoa|atob|encodeURIComponent|decodeURIComponent)$")
          )
          (new_expression
            constructor: (identifier) @ctor
            (#match? @ctor "^(TextEncoder|TextDecoder)$")
          )
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#eq? @obj "Buffer")
            (#match? @prop "^(from|toString)$")
          )
        ]
        """,
        "typescript": r"""
        [
          (call_expression
            function: (identifier) @func
            (#match? @func "^(btoa|atob|encodeURIComponent|decodeURIComponent)$")
          )
          (new_expression
            constructor: (identifier) @ctor
            (#match? @ctor "^(TextEncoder|TextDecoder)$")
          )
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#eq? @obj "Buffer")
            (#match? @prop "^(from|toString)$")
          )
        ]
        """
    },

    "dynamic_code": {
        "javascript": r"""
        [
          (call_expression
            function: (identifier) @func
            (#eq? @func "eval")
          )
          (new_expression
            constructor: (identifier) @func2
            (#eq? @func2 "Function")
          )
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#match? @obj "^(vm)$")
            (#match? @prop "^(runInNewContext|runInThisContext|Script)$")
          )
        ]
        """,
        "typescript": r"""
        [
          (call_expression
            function: (identifier) @func
            (#eq? @func "eval")
          )
          (new_expression
            constructor: (identifier) @func2
            (#eq? @func2 "Function")
          )
          (call_expression
            function: (member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop)
            (#match? @obj "^(vm)$")
            (#match? @prop "^(runInNewContext|runInThisContext|Script)$")
          )
        ]
        """
    },

    # "cookie_access": {
    #     "javascript": r"""
    #     [
    #       (member_expression
    #         object: (identifier) @obj
    #         property: (property_identifier) @prop)
    #       (#match? @obj "^(document)$")
    #       (#eq? @prop "cookie")
    #     ]
    #     """,
    #     "typescript": r"""
    #     [
    #       (member_expression
    #         object: (identifier) @obj
    #         property: (property_identifier) @prop)
    #       (#match? @obj "^(document)$")
    #       (#eq? @prop "cookie")
    #     ]
    #     """
    # }
}


PII_KEYWORDS = re.compile(
    r"""(?ix)
    \b(pass(word|wd)?|passwd|pwd|secret|seckey|apikey|api[_-]?key|token|access[_-]?token|bearer|
       session(id)?|cookie|auth(entication)?|credential(s)?|private[_-]?key|ssh[_-]?key|jwt|refresh[_-]?token)\b
    """,
)

BOOL_FEATURES = ["pii_access",
        "fs_access","process_creation","network_access",
        "crypto_api","data_encoding","dynamic_code",
        "install_scripts",]

VAL_FEATURES = ["entropy_average","entropy_std_dev",]

ALL_FEATURES = BOOL_FEATURES + VAL_FEATURES

CATEGORY_GROUPS = {
    "Sensitive Information Access": ["pii_access"],
    "System Resources and Network Access": ["fs_access", "process_creation", "network_access"],
    "Cryptography and Encoding APIs": ["crypto_api", "data_encoding"],
    "Dynamic Code Execution": ["dynamic_code"],
    "Package Installation Risk": ["install_scripts"]
}


def calculate_shannon_entropy(data):
    if not data:
        return 0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    probabilities = [count / len(data) for count in counts.values()]
    return entropy(probabilities, base=2)

# --- FeatureExtractor ---
class FeatureExtractor:
    def __init__(self):
        self.js_parser = Parser(JS_LANGUAGE)
        self.ts_parser = Parser(TS_LANGUAGE)

    def _query_ast(self, language, tree, source_bytes, query_str):
        query = language.query(query_str)
        captures = query.captures(tree.root_node) 

        results = []
        for capture_name, nodes in captures.items():
            for node in nodes:
                text = source_bytes[node.start_byte:node.end_byte].decode("utf8")
                results.append((capture_name, text))
        return results

    def extract_from_content(self, content, file_path):
        features = {group: 0 for group in CATEGORY_GROUPS}

        # Check for PII
        if PII_KEYWORDS.search(content):
            features["Sensitive Information Access"] = 1

        parser = None
        queries = None
        language = None

        if file_path.endswith('.js'):
            parser = self.js_parser
            language = JS_LANGUAGE
            queries = {k: v.get("javascript") for k,v in ALL_QUERIES.items()}
        elif file_path.endswith('.ts'):
            parser = self.ts_parser
            language = TS_LANGUAGE
            queries = {k: v.get("typescript") for k,v in ALL_QUERIES.items()}

        if parser:
            tree = parser.parse(bytes(content, "utf8"))
            source_bytes = bytes(content, "utf8")

            for feature_name, query_str in queries.items():
                if not query_str:
                    continue
                matches = self._query_ast(language, tree, source_bytes, query_str)
                if matches:
                    # Aggregate features into categories
                    if feature_name in CATEGORY_GROUPS["Sensitive Information Access"]:
                        features["Sensitive Information Access"] = 1
                    if feature_name in CATEGORY_GROUPS["System Resources and Network Access"]:
                        features["System Resources and Network Access"] = 1
                    if feature_name in CATEGORY_GROUPS["Cryptography and Encoding APIs"]:
                        features["Cryptography and Encoding APIs"] = 1
                    if feature_name in CATEGORY_GROUPS["Dynamic Code Execution"]:
                        features["Dynamic Code Execution"] = 1
                    if feature_name in CATEGORY_GROUPS["Package Installation Risk"]:
                        features["Package Installation Risk"] = 1

        return features

        return features

    def extract_from_package(self, package_path):
        aggregated_features = {group: 0 for group in CATEGORY_GROUPS}
        entropies = []
        file_count = 0

        # Check for package.json install scripts
        package_json_path = os.path.join(package_path, 'package.json')
        if os.path.exists(package_json_path):
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    package_json = json.load(f)
                    scripts = package_json.get('scripts', {})
                    if any(s in scripts for s in ['preinstall', 'install', 'postinstall']):
                        aggregated_features["Package Installation Risk"] = 1
            except Exception as e:
                print(f"Error reading package.json: {e}")

        # Process files for feature extraction
        for root, _, files in os.walk(package_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    file_features = self.extract_from_content(content, file)
                    for group, value in file_features.items():
                        aggregated_features[group] += value

                    # Calculate file entropy
                    with open(file_path, 'rb') as bf:
                        byte_content = bf.read()
                    file_entropy = calculate_shannon_entropy(byte_content)
                    entropies.append(file_entropy)
                    file_count += 1
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")
                    pass

        # Add entropy statistics to aggregated features
        if entropies:
            aggregated_features['entropy_average'] = np.mean(entropies)
            aggregated_features['entropy_std_dev'] = np.std(entropies)

        return aggregated_features

def _guess_unpacked_root(tmp_dir: str) -> str:
    """
    Try to infer the root directory after unpacking:
    - If there's only one top-level directory (common 'package/' from npm pack), enter that directory
    - Otherwise use tmp_dir itself
    """
    entries = [e for e in os.listdir(tmp_dir) if not e.startswith('.')]
    if len(entries) == 1:
        candidate = os.path.join(tmp_dir, entries[0])
        if os.path.isdir(candidate):
            return candidate
    return tmp_dir


def _read_pkg_meta(unpacked_path: str):
    """Read name/version from package.json (returns None if not exists or on error)"""
    pkg_json = os.path.join(unpacked_path, 'package.json')
    name = version = None
    if os.path.exists(pkg_json):
        try:
            import json
            with open(pkg_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
                name = data.get('name')
                version = data.get('version')
        except Exception:
            pass
    return name, version


def _is_within_directory(base_dir: str, target_path: str) -> bool:
    base = os.path.abspath(base_dir)
    target = os.path.abspath(target_path)
    try:
        return os.path.commonpath([base]) == os.path.commonpath([base, target])
    except ValueError:
        return False

def _safe_extractall_tar(tar: tarfile.TarFile, path: str):
    for member in tar.getmembers():
        target = os.path.join(path, member.name)
        if not _is_within_directory(path, target):
            raise Exception(f"Blocked path traversal in tar: {member.name}")
    tar.extractall(path)

def _safe_extractall_zip(zf: zipfile.ZipFile, path: str):
    for member in zf.namelist():
        target = os.path.join(path, member)
        if not _is_within_directory(path, target):
            raise Exception(f"Blocked path traversal in zip: {member}")
    zf.extractall(path)

# ---------- Root Directory Inference (More Robust) ----------

def _has_pkg_json(p: str) -> bool:
    return os.path.isfile(os.path.join(p, "package.json"))

def _list_top_level_entries(root: str):
    # Filter hidden and common irrelevant entries (can be modified as needed)
    ignore_names = set()
    entries = []
    for name in os.listdir(root):
        if name.startswith("."):
            continue
        if name in ignore_names:
            continue
        entries.append(os.path.join(root, name))
    return entries

def _guess_unpacked_root(tmp_dir: str) -> str:
    """
    More robust root directory inference logic:
      1) If tmp_dir itself has package.json → use tmp_dir directly
      2) If only one top-level directory → enter that directory (common npm 'package/')
      3) If multiple top-level directories:
         - If exactly one directory contains package.json → choose it
         - If a directory named 'package' exists → choose it
         - Otherwise return tmp_dir (will scan all files during traversal)
    """
    if _has_pkg_json(tmp_dir):
        return tmp_dir

    entries = _list_top_level_entries(tmp_dir)
    dirs = [e for e in entries if os.path.isdir(e)]

    # Single top-level directory
    if len(dirs) == 1:
        only = dirs[0]
        return only if os.path.isdir(only) else tmp_dir

    # Multiple directories: prioritize directory with package.json
    candidates = [d for d in dirs if _has_pkg_json(d)]
    if len(candidates) == 1:
        return candidates[0]

    # Common npm root directory names
    for prefer in ("package",):
        candidate = os.path.join(tmp_dir, prefer)
        if os.path.isdir(candidate):
            return candidate

    # Fallback: use tmp_dir
    return tmp_dir


def _zip_is_encrypted(zf: zipfile.ZipFile) -> bool:
    # 任何条目设置了加密位（flag bit 0x1）即认为加密
    return any((zi.flag_bits & 0x1) != 0 for zi in zf.infolist())

def _safe_extractall_zip(zf: zipfile.ZipFile, path: str, password: bytes | None = None):
    # Path traversal protection
    for member in zf.namelist():
        target = os.path.join(path, member)
        if not _is_within_directory(path, target):
            raise Exception(f"Blocked path traversal in zip: {member}")
    # Extract (pwd can be passed even for unencrypted files, will be ignored)
    zf.extractall(path=path, pwd=password)

# ---------- Unified Entry Point for .tgz/.tar/.zip Processing ----------
def process_package_archive(archive_path: str):
    """
    Unpack + feature extraction, return row dict (for scan_tarballs_to_csv to write to unified large CSV)
    Returns None on failure
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

        try:
            extractor = FeatureExtractor()
            feats = extractor.extract_from_package(unpacked_path)
        except Exception as e:
            print(f"[SKIP] Feature extraction failed for {tarball_name}: {e}")
            return None

        pkg_name, pkg_ver = _read_pkg_meta(unpacked_path)

        row = {
            "tarball": tarball_name,
            "package_name": pkg_name or Path(archive_path).stem.replace(".tgz", "").replace(".tar", "").replace(".zip", ""),
            "package_version": pkg_ver or "",
        }
        row.update(feats)
        return row

def scan_tarballs_to_csv(tarballs_dir: str, out_csv: str, max_workers: int = 1):
    feature_cols = VAL_FEATURES + list(CATEGORY_GROUPS.keys())  # Include category group names
    meta_cols = ["tarball", "package_name", "package_version"]
    header = meta_cols + feature_cols  # Ensure the header includes the new categories

    write_header = not os.path.exists(out_csv)

    # Collect archive paths
    archive_paths = []
    for root, _, files in os.walk(tarballs_dir):
        for fn in files:
            lower = fn.lower()
            if lower.endswith((".tgz", ".tar.gz", ".tar", ".zip")):
                archive_paths.append(os.path.join(root, fn))

    print(f"Found {len(archive_paths)} archives under {tarballs_dir}")

    # Parallel processing and real-time writing
    with open(out_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        if write_header:
            writer.writeheader()

        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_package_archive, path): path for path in archive_paths}

            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Processing archives"):
                path = futures[future]
                try:
                    row = future.result()
                    if not row:
                        print(f"\n[ERROR] {path}: Processing returned no data.")
                        continue

                    # Ensure all columns are in the row, set missing ones to 0 or empty
                    for col in header:
                        if col not in row:
                            if col in feature_cols:
                                row[col] = 0
                            else:
                                row[col] = ""

                    writer.writerow(row)
                    f.flush()
                except Exception as e:
                    print(f"\n[ERROR] {path}: {e}")

    print(f"✅ Done. Results written to {out_csv}")

    
if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Batch scan npm package archives and extract features to CSV.")
  parser.add_argument('--dataset', type=str, required=True, help='Directory containing package archives (.tgz/.tar.gz/.tar/.zip)')
  parser.add_argument('--out', type=str, required=True, help='Output CSV file path')
  parser.add_argument('--max_workers', type=int, default=None, help='Maximum number of parallel workers')
  args = parser.parse_args()

  os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
  scan_tarballs_to_csv(args.dataset, args.out, max_workers=args.max_workers)
  print(f"Done. CSV at: {os.path.abspath(args.out)}")