import { strToU8, zipSync } from 'fflate';

export interface LinuxBundleFile {
  filename: string;
  label: string;
  language: string;
  executable?: boolean;
  content: string;
}

export const KRYPTLOCK_PY = `#!/usr/bin/env python3
"""
KryptLock - Native Linux Multi-Format Compression & Encrypted Archive Utility
Supports:
  - .klock (KLOCK001: AES-256-GCM + Deflate/Gzip/Bzip2/LZMA/Store + SHA-256)
  - .rar   (Create via 'rar', extract/unrar via 'unrar' / 'rar' / '7z' / 'unar' with & without passwords)
  - .7z    (Create & extract via '7z' / '7zz' with & without AES-256 + header encryption)
  - .zip   (Create & extract with & without AES-256 / ZipCrypto passwords)
  - .gz / .tar.gz / .tgz, .bz2 / .tar.bz2, .xz / .tar.xz, .tar
"""

import argparse
import bz2
import getpass
import gzip
import hashlib
import json
import lzma
import math
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import urllib.parse
import zipfile
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

MAGIC = b"KLOCK001"
HEADER_LENGTH = 41  # 8 magic + 1 flag + 4 iterations + 16 salt + 12 iv
DEFAULT_ITERATIONS = 600_000

ALGO_TO_FLAG: Dict[str, int] = {
    "deflate": 0x01,
    "store": 0x02,
    "gzip": 0x03,
    "bzip2": 0x04,
    "lzma": 0x05,
}
FLAG_TO_ALGO: Dict[int, str] = {v: k for k, v in ALGO_TO_FLAG.items()}

SUPPORTED_PACK_FORMATS = [
    "klock",
    "rar",
    "7z",
    "zip",
    "tar.gz",
    "gz",
    "tar.bz2",
    "bz2",
    "tar.xz",
    "xz",
    "tar",
]


class IntegrityError(Exception):
    """Raised when an archive or extracted file fails SHA-256 verification."""


def require_cryptography() -> None:
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError(
            "Python 'cryptography' package is required for .klock AES-256-GCM archives.\\n"
            "Install on Ubuntu/Debian: sudo apt install python3-cryptography\\n"
            "Install on Fedora:        sudo dnf install python3-cryptography\\n"
            "Install on Arch:          sudo pacman -S python-cryptography"
        )


def find_7z_binary() -> Optional[str]:
    return shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")


def detect_available_backends() -> dict:
    return {
        "klock_aes_gcm": HAS_CRYPTOGRAPHY,
        "rar_create": shutil.which("rar"),
        "rar_extract": shutil.which("unrar") or shutil.which("rar") or find_7z_binary() or shutil.which("unar"),
        "7z": find_7z_binary(),
        "zip_cli": shutil.which("zip"),
        "unzip_cli": shutil.which("unzip"),
        "python_stdlib": "zipfile, tarfile, gzip, bz2, lzma, zlib",
    }


def evaluate_password_strength(password: str, has_keyfile: bool = False) -> dict:
    if not password and not has_keyfile:
        return {
            "bits": 0,
            "score": 0,
            "label": "Empty",
            "hints": ["Enter a password (12+ characters recommended)."],
        }

    charset = 0
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        charset += 32

    base_bits = len(password) * (math.log2(charset) if charset > 0 else 0.0)
    bits = round(base_bits + (128 if has_keyfile else 0))

    hints: List[str] = []
    if len(password) < 12:
        hints.append("Use at least 12 characters")
    if not has_upper:
        hints.append("Add uppercase letters")
    if not has_digit:
        hints.append("Add digits")
    if not has_symbol:
        hints.append("Add symbols or hyphens")

    if bits >= 96:
        return {"bits": bits, "score": 4, "label": "Very Strong", "hints": []}
    if bits >= 64:
        return {"bits": bits, "score": 3, "label": "Strong", "hints": hints[:1]}
    if bits >= 40:
        return {"bits": bits, "score": 2, "label": "Moderate", "hints": hints[:2]}
    return {"bits": bits, "score": 1, "label": "Weak", "hints": hints}


def normalize_expected_checksum(raw_value: str) -> str:
    candidate = raw_value.strip()
    path = Path(candidate)
    if path.is_file():
        candidate = path.read_text(encoding="utf-8", errors="replace").strip()
    match = re.search(r"([a-fA-F0-9]{64})", candidate)
    if not match:
        raise ValueError("Expected checksum must be a 64-character SHA-256 hex digest or .sha256 file.")
    return match.group(1).lower()


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_secret_material(passphrase: str, keyfile_path: Optional[Path] = None) -> bytes:
    if keyfile_path is not None:
        keyfile_bytes = keyfile_path.read_bytes()
        if len(keyfile_bytes) > 0:
            digest = hashlib.sha256(keyfile_bytes).hexdigest()
            return f"{passphrase}:{digest}".encode("utf-8")
    return passphrase.encode("utf-8")


def derive_aes_key(secret: bytes, salt: bytes, iterations: int) -> bytes:
    require_cryptography()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(secret)


def compress_payload(data: bytes, algorithm: str, level: int = 6) -> bytes:
    lvl = max(1, min(9, level))
    if algorithm == "store":
        return data
    if algorithm == "deflate":
        return zlib.compress(data, level=lvl)
    if algorithm == "gzip":
        return gzip.compress(data, compresslevel=lvl)
    if algorithm == "bzip2":
        return bz2.compress(data, compresslevel=lvl)
    if algorithm == "lzma":
        return lzma.compress(data, format=lzma.FORMAT_ALONE, preset=lvl)
    raise ValueError(f"Unsupported compression algorithm: {algorithm}")


def decompress_payload(data: bytes, algorithm: str) -> bytes:
    if algorithm == "store":
        return data
    if algorithm == "deflate":
        return zlib.decompress(data)
    if algorithm == "gzip":
        return gzip.decompress(data)
    if algorithm == "bzip2":
        return bz2.decompress(data)
    if algorithm == "lzma":
        return lzma.decompress(data, format=lzma.FORMAT_ALONE)
    raise ValueError(f"Unsupported compression algorithm: {algorithm}")


def collect_input_files(paths: List[Path]) -> List[Tuple[Path, str]]:
    collected: List[Tuple[Path, str]] = []
    for raw_path in paths:
        target = raw_path.resolve()
        if not target.exists():
            raise FileNotFoundError(f"Path not found: {raw_path}")
        if target.is_file():
            collected.append((target, target.name))
        elif target.is_dir():
            base_parent = target.parent
            for root, _, filenames in os.walk(target):
                for fname in sorted(filenames):
                    fpath = Path(root) / fname
                    rel = fpath.relative_to(base_parent).as_posix()
                    collected.append((fpath, rel))
    return collected


def detect_archive_format(archive_path: Path) -> str:
    head = archive_path.read_bytes()[:512]
    lower = archive_path.name.lower()
    if head.startswith(MAGIC):
        return "klock"
    if head.startswith(b"Rar!\\x1a\\x07"):
        return "rar"
    if head.startswith(b"7z\\xbc\\xaf\\x27\\x1c"):
        return "7z"
    if head.startswith((b"PK\\x03\\x04", b"PK\\x05\\x06")):
        return "zip"
    if head.startswith(b"\\x1f\\x8b"):
        return "tar.gz" if lower.endswith((".tar.gz", ".tgz")) else "gz"
    if head.startswith(b"BZh"):
        return "tar.bz2" if lower.endswith((".tar.bz2", ".tbz2", ".tbz")) else "bz2"
    if head.startswith(b"\\xfd7zXZ\\x00"):
        return "tar.xz" if lower.endswith((".tar.xz", ".txz")) else "xz"
    if len(head) >= 263 and head[257:262] == b"ustar":
        return "tar"

    for ext, fmt in [
        (".klock", "klock"),
        (".rar", "rar"),
        (".7z", "7z"),
        (".zip", "zip"),
        (".tar.gz", "tar.gz"),
        (".tgz", "tar.gz"),
        (".gz", "gz"),
        (".tar.bz2", "tar.bz2"),
        (".tbz2", "tar.bz2"),
        (".bz2", "bz2"),
        (".tar.xz", "tar.xz"),
        (".txz", "tar.xz"),
        (".xz", "xz"),
        (".tar", "tar"),
    ]:
        if lower.endswith(ext):
            return fmt
    raise ValueError(f"Unrecognized archive format: {archive_path.name}")


def format_from_output_name(output_path: Path, explicit_format: Optional[str] = None) -> str:
    if explicit_format:
        return explicit_format
    lower = output_path.name.lower()
    for ext, fmt in [
        (".klock", "klock"),
        (".rar", "rar"),
        (".7z", "7z"),
        (".zip", "zip"),
        (".tar.gz", "tar.gz"),
        (".tgz", "tar.gz"),
        (".gz", "gz"),
        (".tar.bz2", "tar.bz2"),
        (".tbz2", "tar.bz2"),
        (".bz2", "bz2"),
        (".tar.xz", "tar.xz"),
        (".txz", "tar.xz"),
        (".xz", "xz"),
        (".tar", "tar"),
    ]:
        if lower.endswith(ext):
            return fmt
    return "klock"


def encrypt_archive(
    input_paths: List[Path],
    output_path: Path,
    passphrase: str,
    keyfile_path: Optional[Path] = None,
    algorithm: str = "deflate",
    level: int = 6,
    iterations: int = DEFAULT_ITERATIONS,
    write_checksum_file: bool = False,
) -> dict:
    require_cryptography()
    if algorithm not in ALGO_TO_FLAG:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {', '.join(ALGO_TO_FLAG)}")

    files = collect_input_files(input_paths)
    if not files:
        raise ValueError("No files found to lock.")

    entries_meta = []
    chunks: List[bytes] = []

    for abs_path, rel_path in files:
        data = abs_path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        stat = abs_path.stat()
        entries_meta.append(
            {
                "path": rel_path,
                "size": len(data),
                "mtime": int(stat.st_mtime * 1000),
                "sha256": sha,
            }
        )
        chunks.append(data)

    raw_payload = b"".join(chunks)
    payload_sha256 = hashlib.sha256(raw_payload).hexdigest()

    manifest = {
        "version": 2,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "compressionAlgorithm": algorithm,
        "payloadSha256": payload_sha256,
        "entries": entries_meta,
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    inner_container = struct.pack(">I", len(manifest_bytes)) + manifest_bytes + raw_payload

    flag = ALGO_TO_FLAG[algorithm]
    compressed_payload = compress_payload(inner_container, algorithm, level=level)

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    header = MAGIC + bytes([flag]) + struct.pack(">I", iterations) + salt + iv

    secret = build_secret_material(passphrase, keyfile_path)
    aes_key = derive_aes_key(secret, salt, iterations)
    ciphertext = AESGCM(aes_key).encrypt(iv, compressed_payload, header)

    archive_bytes = header + ciphertext
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    output_path.write_bytes(archive_bytes)

    checksum_path: Optional[Path] = None
    if write_checksum_file:
        checksum_path = Path(f"{output_path}.sha256")
        checksum_path.write_text(f"{archive_sha256}  {output_path.name}\\n", encoding="utf-8")

    return {
        "output": str(output_path),
        "format": "klock",
        "algorithm": algorithm,
        "entries": len(entries_meta),
        "uncompressed": len(inner_container),
        "compressed": len(compressed_payload),
        "archive_size": len(archive_bytes),
        "archive_sha256": archive_sha256,
        "payload_sha256": payload_sha256,
        "checksum_file": str(checksum_path) if checksum_path else None,
    }


def inspect_archive(archive_path: Path) -> dict:
    raw = archive_path.read_bytes()
    if len(raw) < HEADER_LENGTH + 16:
        raise ValueError("File is too small to be a valid .klock archive.")
    magic = raw[:8]
    if magic != MAGIC:
        raise ValueError(f"Invalid magic header: {magic!r}")
    flag = raw[8]
    if flag not in FLAG_TO_ALGO:
        raise ValueError(f"Unsupported compression flag: 0x{flag:02x}")
    (iterations,) = struct.unpack(">I", raw[9:13])
    salt = raw[13:29]
    iv = raw[29:41]
    return {
        "magic": magic.decode("ascii"),
        "format": "klock",
        "compression": FLAG_TO_ALGO[flag],
        "iterations": iterations,
        "salt_hex": salt.hex(),
        "iv_hex": iv.hex(),
        "total_bytes": len(raw),
        "ciphertext_bytes": len(raw) - HEADER_LENGTH,
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
    }


def inspect_any_archive(archive_path: Path) -> dict:
    fmt = detect_archive_format(archive_path)
    if fmt == "klock":
        return inspect_archive(archive_path)
    return {
        "magic": fmt.upper(),
        "format": fmt,
        "compression": fmt,
        "total_bytes": archive_path.stat().st_size,
        "archive_sha256": compute_file_sha256(archive_path),
    }


def decrypt_archive_to_memory(
    archive_path: Path,
    passphrase: str,
    keyfile_path: Optional[Path] = None,
    expected_checksum: Optional[str] = None,
) -> Tuple[dict, List[Tuple[dict, bytes, bool]], dict]:
    require_cryptography()
    raw = archive_path.read_bytes()
    info = inspect_archive(archive_path)

    if expected_checksum:
        expected_hex = normalize_expected_checksum(expected_checksum)
        if info["archive_sha256"] != expected_hex:
            raise IntegrityError(
                f"Archive SHA-256 mismatch! Expected {expected_hex}, computed {info['archive_sha256']}."
            )

    header = raw[:HEADER_LENGTH]
    salt = raw[13:29]
    iv = raw[29:41]
    ciphertext = raw[HEADER_LENGTH:]

    secret = build_secret_material(passphrase, keyfile_path)
    aes_key = derive_aes_key(secret, salt, info["iterations"])
    try:
        payload = AESGCM(aes_key).decrypt(iv, ciphertext, header)
    except Exception as exc:
        raise ValueError(
            "Decryption failed: incorrect password, missing keyfile, or corrupted archive."
        ) from exc

    inner_container = decompress_payload(payload, info["compression"])
    (manifest_len,) = struct.unpack(">I", inner_container[:4])
    manifest = json.loads(inner_container[4 : 4 + manifest_len].decode("utf-8"))

    raw_payload = inner_container[4 + manifest_len :]
    computed_payload_sha = hashlib.sha256(raw_payload).hexdigest()
    stored_payload_sha = manifest.get("payloadSha256")
    container_ok = stored_payload_sha is None or stored_payload_sha == computed_payload_sha

    cursor = 0
    extracted = []
    failed_paths: List[str] = []
    for entry in manifest["entries"]:
        size = entry["size"]
        data = raw_payload[cursor : cursor + size]
        cursor += size
        actual_sha = hashlib.sha256(data).hexdigest()
        ok = actual_sha == entry["sha256"]
        if not ok:
            failed_paths.append(entry["path"])
        extracted.append((entry, data, ok))

    integrity = {
        "archive_sha256": info["archive_sha256"],
        "container_ok": container_ok,
        "all_files_ok": container_ok and len(failed_paths) == 0,
        "failed_paths": failed_paths,
    }
    return manifest, extracted, integrity


def safe_extract_path(output_dir: Path, rel_path: str) -> Path:
    dest = (output_dir / rel_path).resolve()
    root = output_dir.resolve()
    if root not in dest.parents and dest != root:
        raise ValueError(f"Blocked unsafe archive path traversal: {rel_path}")
    return dest


def unlock_archive(
    archive_path: Path,
    output_dir: Path,
    passphrase: str,
    keyfile_path: Optional[Path] = None,
    expected_checksum: Optional[str] = None,
) -> Tuple[List[Tuple[str, int, bool]], dict]:
    _, extracted, integrity = decrypt_archive_to_memory(
        archive_path,
        passphrase,
        keyfile_path=keyfile_path,
        expected_checksum=expected_checksum,
    )
    if not integrity["all_files_ok"]:
        raise IntegrityError(
            f"Integrity check failed for: {', '.join(integrity['failed_paths']) or 'inner container'}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for entry, data, verified in extracted:
        dest = safe_extract_path(output_dir, entry["path"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        results.append((entry["path"], entry["size"], verified))
    return results, integrity


def pack_archive(
    input_paths: List[Path],
    output_path: Path,
    fmt: Optional[str] = None,
    passphrase: Optional[str] = None,
    keyfile_path: Optional[Path] = None,
    algorithm: str = "deflate",
    level: int = 6,
    iterations: int = DEFAULT_ITERATIONS,
    encrypt_headers: bool = True,
    zip_crypto: bool = False,
    write_checksum_file: bool = False,
) -> dict:
    resolved_fmt = format_from_output_name(output_path, fmt)
    if resolved_fmt == "klock":
        if not passphrase and keyfile_path is None:
            raise ValueError("A password or keyfile is required for .klock archives.")
        return encrypt_archive(
            input_paths,
            output_path,
            passphrase or "",
            keyfile_path=keyfile_path,
            algorithm=algorithm,
            level=level,
            iterations=iterations,
            write_checksum_file=write_checksum_file,
        )

    files = collect_input_files(input_paths)
    if not files:
        raise ValueError("No files found to pack.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    out_abs = output_path.resolve()
    if out_abs.exists():
        out_abs.unlink()

    if resolved_fmt == "rar":
        rar_bin = shutil.which("rar")
        if not rar_bin:
            raise RuntimeError(
                "Creating .rar archives requires the Linux 'rar' CLI binary.\\n"
                "Install it on Ubuntu/Debian: sudo apt install rar\\n"
                "Or use .7z / .zip / .klock which work out of the box."
            )
        rar_lvl = min(5, max(0, round((level / 9) * 5)))
        cmd = [rar_bin, "a", "-r", "-ep1", f"-m{rar_lvl}"]
        if passphrase:
            cmd.append(f"-hp{passphrase}" if encrypt_headers else f"-p{passphrase}")
        cmd.append(str(out_abs))
        cmd.extend(str(p.resolve()) for p in input_paths)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "rar failed.")

    elif resolved_fmt == "7z":
        sz_bin = find_7z_binary()
        if not sz_bin:
            raise RuntimeError(
                "Creating .7z archives requires 7-Zip ('p7zip-full' or '7zip').\\n"
                "Install on Ubuntu/Debian: sudo apt install p7zip-full\\n"
                "Install on Fedora:        sudo dnf install p7zip p7zip-plugins\\n"
                "Install on Arch:          sudo pacman -S 7zip"
            )
        cmd = [sz_bin, "a", "-t7z", f"-mx={max(1, min(9, level))}"]
        if passphrase:
            cmd.append(f"-p{passphrase}")
            if encrypt_headers:
                cmd.append("-mhe=on")
        cmd.append(str(out_abs))
        cmd.extend(str(p.resolve()) for p in input_paths)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "7z failed.")

    elif resolved_fmt == "zip":
        if passphrase:
            sz_bin = find_7z_binary()
            zip_bin = shutil.which("zip")
            if sz_bin:
                method = "ZipCrypto" if zip_crypto else "AES256"
                cmd = [sz_bin, "a", "-tzip", f"-mx={max(1, min(9, level))}", f"-mem={method}", f"-p{passphrase}", str(out_abs)]
                cmd.extend(str(p.resolve()) for p in input_paths)
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "7z zip creation failed.")
            elif zip_bin:
                cmd = [zip_bin, "-r", "-P", passphrase, str(out_abs)]
                cmd.extend(str(p) for p in input_paths)
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "zip failed.")
            else:
                raise RuntimeError("Password-protected .zip creation requires '7z' (p7zip-full) or 'zip'.")
        else:
            with zipfile.ZipFile(out_abs, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=max(1, min(9, level))) as zf:
                for abs_path, rel_path in files:
                    zf.write(abs_path, arcname=rel_path)

    elif resolved_fmt in ("gz", "bz2", "xz"):
        if len(files) > 1:
            raise ValueError(f"Single-stream .{resolved_fmt} holds 1 file. Use .tar.{resolved_fmt} for multiple files.")
        raw_bytes = files[0][0].read_bytes()
        if resolved_fmt == "gz":
            out_abs.write_bytes(gzip.compress(raw_bytes, compresslevel=max(1, min(9, level))))
        elif resolved_fmt == "bz2":
            out_abs.write_bytes(bz2.compress(raw_bytes, compresslevel=max(1, min(9, level))))
        else:
            out_abs.write_bytes(lzma.compress(raw_bytes, preset=max(1, min(9, level))))

    elif resolved_fmt in ("tar.gz", "tar.bz2", "tar.xz", "tar"):
        mode_map = {"tar": "w", "tar.gz": "w:gz", "tar.bz2": "w:bz2", "tar.xz": "w:xz"}
        with tarfile.open(out_abs, mode=mode_map[resolved_fmt]) as tf:
            for abs_path, rel_path in files:
                tf.add(abs_path, arcname=rel_path)
    else:
        raise ValueError(f"Unsupported output format: {resolved_fmt}")

    archive_sha256 = compute_file_sha256(out_abs)
    checksum_path: Optional[Path] = None
    if write_checksum_file:
        checksum_path = Path(f"{out_abs}.sha256")
        checksum_path.write_text(f"{archive_sha256}  {out_abs.name}\\n", encoding="utf-8")

    return {
        "output": str(out_abs),
        "format": resolved_fmt,
        "algorithm": resolved_fmt,
        "entries": len(files),
        "encrypted": bool(passphrase),
        "archive_size": out_abs.stat().st_size,
        "archive_sha256": archive_sha256,
        "checksum_file": str(checksum_path) if checksum_path else None,
    }


def unpack_archive(
    archive_path: Path,
    output_dir: Path,
    passphrase: Optional[str] = None,
    keyfile_path: Optional[Path] = None,
    expected_checksum: Optional[str] = None,
) -> Tuple[List[Tuple[str, int, bool]], dict]:
    if not archive_path.is_file():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    actual_sha = compute_file_sha256(archive_path)
    if expected_checksum:
        expected_hex = normalize_expected_checksum(expected_checksum)
        if actual_sha != expected_hex:
            raise IntegrityError(f"Archive SHA-256 mismatch! Expected {expected_hex}, computed {actual_sha}.")

    fmt = detect_archive_format(archive_path)
    if fmt == "klock":
        return unlock_archive(
            archive_path,
            output_dir,
            passphrase or "",
            keyfile_path=keyfile_path,
            expected_checksum=expected_checksum,
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    out_abs = output_dir.resolve()
    arc_abs = archive_path.resolve()

    if fmt == "rar":
        unrar_bin = shutil.which("unrar") or shutil.which("rar")
        sz_bin = find_7z_binary()
        unar_bin = shutil.which("unar")
        if unrar_bin:
            pw_flag = f"-p{passphrase}" if passphrase else "-p-"
            proc = subprocess.run([unrar_bin, "x", "-o+", pw_flag, str(arc_abs), f"{out_abs}/"], capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "unrar failed (wrong or missing password).")
        elif sz_bin:
            pw_flag = f"-p{passphrase}" if passphrase else "-p-"
            proc = subprocess.run([sz_bin, "x", "-y", pw_flag, f"-o{out_abs}", str(arc_abs)], capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "7z RAR extraction failed.")
        elif unar_bin:
            cmd = [unar_bin, "-force-overwrite", "-output-directory", str(out_abs)]
            if passphrase:
                cmd.extend(["-password", passphrase])
            cmd.append(str(arc_abs))
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "unar failed.")
        else:
            raise RuntimeError("Extracting .rar requires 'unrar', 'rar', 'unar', or '7z' (with RAR plugin).")

    elif fmt == "7z":
        sz_bin = find_7z_binary()
        if not sz_bin:
            raise RuntimeError("Extracting .7z requires '7z' (install p7zip-full or 7zip).")
        pw_flag = f"-p{passphrase}" if passphrase else "-p-"
        proc = subprocess.run([sz_bin, "x", "-y", pw_flag, f"-o{out_abs}", str(arc_abs)], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "7z extraction failed.")

    elif fmt == "zip":
        extracted_with_python = False
        try:
            with zipfile.ZipFile(arc_abs, "r") as zf:
                pwd_bytes = passphrase.encode("utf-8") if passphrase else None
                for member in zf.infolist():
                    if member.is_dir():
                        continue
                    dest = safe_extract_path(out_abs, member.filename)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member, mode="r", pwd=pwd_bytes) as src:
                        dest.write_bytes(src.read())
                extracted_with_python = True
        except NotImplementedError:
            extracted_with_python = False
        except RuntimeError as exc:
            if "encrypted" in str(exc).lower() or "password" in str(exc).lower():
                raise ValueError("ZIP password is missing or incorrect.") from exc
            extracted_with_python = False

        if not extracted_with_python:
            sz_bin = find_7z_binary()
            unzip_bin = shutil.which("unzip")
            if sz_bin:
                pw_flag = f"-p{passphrase}" if passphrase else "-p-"
                proc = subprocess.run([sz_bin, "x", "-y", pw_flag, f"-o{out_abs}", str(arc_abs)], capture_output=True, text=True)
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "ZIP extraction failed.")
            elif unzip_bin:
                cmd = [unzip_bin, "-o"]
                if passphrase:
                    cmd.extend(["-P", passphrase])
                cmd.extend([str(arc_abs), "-d", str(out_abs)])
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "unzip failed.")
            else:
                raise RuntimeError("This ZIP uses AES encryption. Install 'p7zip-full' (7z) or 'unzip'.")

    elif fmt in ("tar", "tar.gz", "tar.bz2", "tar.xz"):
        with tarfile.open(arc_abs, mode="r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                dest = safe_extract_path(out_abs, member.name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src is not None:
                    dest.write_bytes(src.read())

    elif fmt in ("gz", "bz2", "xz"):
        stem = re.sub(r"\\.(gz|gzip|bz2|xz)$", "", arc_abs.name, flags=re.IGNORECASE) or "extracted.bin"
        dest = safe_extract_path(out_abs, stem)
        raw_bytes = arc_abs.read_bytes()
        if fmt == "gz":
            dest.write_bytes(gzip.decompress(raw_bytes))
        elif fmt == "bz2":
            dest.write_bytes(bz2.decompress(raw_bytes))
        else:
            dest.write_bytes(lzma.decompress(raw_bytes))

    extracted_summary: List[Tuple[str, int, bool]] = []
    for root, _, filenames in os.walk(out_abs):
        for fname in sorted(filenames):
            fpath = Path(root) / fname
            extracted_summary.append((fpath.relative_to(out_abs).as_posix(), fpath.stat().st_size, True))
    return extracted_summary, {
        "archive_sha256": actual_sha,
        "format": fmt,
        "all_files_ok": True,
    }


def open_email_composer(
    archive_path: Path,
    recipient: str,
    subject: Optional[str] = None,
    include_checksum: bool = True,
) -> str:
    resolved = archive_path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    info = inspect_any_archive(resolved)
    mail_subject = subject or f"Archive: {resolved.name}"
    body_lines = [
        f"Attached is the archive ({resolved.name}) created with KryptLock.",
        "",
        f"Format: {info['format']} ({info['compression']})",
        f"Size: {info['total_bytes']} bytes",
    ]
    if include_checksum:
        body_lines.append(f"SHA-256 Checksum: {info['archive_sha256']}")
    body_lines.extend(
        [
            "",
            "To unpack: open with KryptLock (kryptlock-gui) or run:",
            f"  kryptlock unpack {resolved.name} -o ./restored",
            "",
            "Note: If password-protected, the password will be shared separately.",
        ]
    )
    body = "\\n".join(body_lines)

    sidecar = Path(f"{resolved}.sha256")
    xdg_email = shutil.which("xdg-email")
    if xdg_email:
        cmd = [xdg_email, "--subject", mail_subject, "--body", body, "--attach", str(resolved)]
        if include_checksum and sidecar.is_file():
            cmd.extend(["--attach", str(sidecar)])
        if recipient.strip():
            cmd.append(recipient.strip())
        subprocess.Popen(cmd)
        return "xdg-email"

    thunderbird = shutil.which("thunderbird")
    if thunderbird:
        attachments = [str(resolved)]
        if include_checksum and sidecar.is_file():
            attachments.append(str(sidecar))
        compose_arg = (
            f"to='{recipient.strip()}',subject='{mail_subject}',"
            f"body='{body}',attachment='{','.join(attachments)}'"
        )
        subprocess.Popen([thunderbird, "-compose", compose_arg])
        return "thunderbird"

    xdg_open = shutil.which("xdg-open")
    if xdg_open:
        mailto = (
            f"mailto:{urllib.parse.quote(recipient.strip())}"
            f"?subject={urllib.parse.quote(mail_subject)}"
            f"&body={urllib.parse.quote(body)}"
        )
        subprocess.Popen([xdg_open, mailto])
        return "mailto"

    raise RuntimeError(
        "No Linux email launcher found (install xdg-utils or thunderbird)."
    )


def prompt_passphrase(confirm: bool = False, allow_empty: bool = False) -> str:
    pw = getpass.getpass("Password (leave empty for none): " if allow_empty else "Password: ")
    if not pw and allow_empty:
        return ""
    if confirm:
        strength = evaluate_password_strength(pw)
        print(f"Password strength: {strength['label']} ({strength['bits']} bits)")
        if strength["hints"]:
            print(f"Tip: {'; '.join(strength['hints'])}")
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            raise ValueError("Passwords do not match.")
    return pw


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="kryptlock",
        description="KryptLock - Linux Multi-Format Compression (KLOCK/RAR/7z/ZIP/Gzip/Bzip2/XZ) & Encryption Tool",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_lock = sub.add_parser("lock", help="Compress and encrypt files/folders into a .klock archive")
    p_lock.add_argument("output", type=Path, help="Output .klock archive file")
    p_lock.add_argument("inputs", nargs="+", type=Path, help="Files or directories to lock")
    p_lock.add_argument("-a", "--algo", choices=list(ALGO_TO_FLAG.keys()), default="deflate")
    p_lock.add_argument("--level", type=int, default=6, choices=range(1, 10))
    p_lock.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    p_lock.add_argument("--keyfile", type=Path, default=None)
    p_lock.add_argument("--write-checksum", action="store_true")
    p_lock.add_argument("--email", type=str, default=None)

    p_pack = sub.add_parser("pack", help="Pack files into .klock, .rar, .7z, .zip, .tar.gz/.gz, .tar.bz2/.bz2, or .tar.xz/.xz")
    p_pack.add_argument("output", type=Path, help="Output archive file (.rar, .7z, .zip, .tar.gz, .klock, ...)")
    p_pack.add_argument("inputs", nargs="+", type=Path, help="Files or directories to pack")
    p_pack.add_argument("-f", "--format", choices=SUPPORTED_PACK_FORMATS, default=None)
    p_pack.add_argument("-a", "--algo", choices=list(ALGO_TO_FLAG.keys()), default="deflate", help=".klock inner compression")
    p_pack.add_argument("--level", type=int, default=6, choices=range(1, 10))
    p_pack.add_argument("--no-password", action="store_true", help="Create unencrypted archive without password prompt")
    p_pack.add_argument("--encrypt-headers", action="store_true", help="Encrypt filenames/headers (.rar -hp / .7z -mhe)")
    p_pack.add_argument("--zip-crypto", action="store_true", help="Use legacy ZipCrypto instead of AES-256 for .zip")
    p_pack.add_argument("--keyfile", type=Path, default=None)
    p_pack.add_argument("--write-checksum", action="store_true")
    p_pack.add_argument("--email", type=str, default=None)

    p_unpack = sub.add_parser("unpack", help="Extract .klock, .rar (unrar), .7z, .zip, .gz/.tar.gz, .bz2, .xz, or .tar")
    p_unpack.add_argument("archive", type=Path, help="Input archive path")
    p_unpack.add_argument("-o", "--output", type=Path, default=Path("."), help="Destination directory")
    p_unpack.add_argument("--no-password", action="store_true", help="Do not prompt for a password")
    p_unpack.add_argument("--keyfile", type=Path, default=None)
    p_unpack.add_argument("--checksum", type=str, default=None, help="Expected SHA-256 hex or .sha256 file")

    p_unlock = sub.add_parser("unlock", help="Decrypt, verify checksums, and extract a .klock archive")
    p_unlock.add_argument("archive", type=Path)
    p_unlock.add_argument("-o", "--output", type=Path, default=Path("."))
    p_unlock.add_argument("--keyfile", type=Path, default=None)
    p_unlock.add_argument("--checksum", type=str, default=None)

    p_verify = sub.add_parser("verify", help="Verify .klock archive SHA-256 and encrypted file integrity")
    p_verify.add_argument("archive", type=Path)
    p_verify.add_argument("--keyfile", type=Path, default=None)
    p_verify.add_argument("--checksum", type=str, default=None)

    p_email = sub.add_parser("email", help="Compose an email with a compressed/locked archive attached")
    p_email.add_argument("archive", type=Path)
    p_email.add_argument("--to", type=str, default="")
    p_email.add_argument("--subject", type=str, default=None)
    p_email.add_argument("--no-checksum", action="store_true")

    p_list = sub.add_parser("list", help="Decrypt .klock manifest and list archive entries")
    p_list.add_argument("archive", type=Path)
    p_list.add_argument("--keyfile", type=Path, default=None)

    p_inspect = sub.add_parser("inspect", help="Inspect archive format, header, and SHA-256")
    p_inspect.add_argument("archive", type=Path)

    p_keygen = sub.add_parser("keygen", help="Generate a 64-byte CSPRNG keyfile")
    p_keygen.add_argument("output", type=Path)

    sub.add_parser("formats", help="Show detected Linux archive backends (rar, unrar, 7z, zip, python)")
    sub.add_parser("guide", help="Print a step-by-step how-to-use guide for CLI and GUI")

    args = parser.parse_args()

    try:
        if args.command == "formats":
            print(json.dumps(detect_available_backends(), indent=2))
        elif args.command == "guide":
            print(
                "KryptLock — Quick Usage Guide\\n"
                "==============================\\n"
                "1. Launch Desktop GUI:  kryptlock-gui  (or press Super and search KryptLock)\\n"
                "2. Lock with .klock:    kryptlock lock secrets.klock ./files --algo lzma --write-checksum\\n"
                "3. Pack .rar / .7z/.zip: kryptlock pack out.rar ./files --encrypt-headers\\n"
                "   (use --no-password for unencrypted .rar, .7z, or .zip)\\n"
                "4. Unpack any format:   kryptlock unpack archive.rar -o ./restored\\n"
                "5. Verify .klock:       kryptlock verify secrets.klock --checksum secrets.klock.sha256\\n"
                "6. Email archive:       kryptlock email secrets.klock --to colleague@example.com\\n"
                "7. Check backends:      kryptlock formats\\n"
            )
        elif args.command == "inspect":
            info = inspect_any_archive(args.archive)
            print(json.dumps(info, indent=2))
        elif args.command == "keygen":
            args.output.write_bytes(secrets.token_bytes(64))
            os.chmod(args.output, 0o600)
            print(f"Generated 512-bit keyfile: {args.output} (chmod 600)")
        elif args.command == "email":
            launcher = open_email_composer(
                args.archive,
                recipient=args.to,
                subject=args.subject,
                include_checksum=not args.no_checksum,
            )
            print(f"Opened mail composer ({launcher}) with attachment: {args.archive}")
        elif args.command == "lock":
            pw = prompt_passphrase(confirm=True)
            res = encrypt_archive(
                args.inputs,
                args.output,
                pw,
                keyfile_path=args.keyfile,
                algorithm=args.algo,
                level=args.level,
                iterations=args.iterations,
                write_checksum_file=args.write_checksum,
            )
            print(f"Locked {res['entries']} file(s) [{res['algorithm']}] -> {res['output']} ({res['archive_size']} bytes)")
            print(f"Archive SHA-256: {res['archive_sha256']}")
            if res["checksum_file"]:
                print(f"Saved checksum:  {res['checksum_file']}")
            if args.email:
                launcher = open_email_composer(args.output, recipient=args.email)
                print(f"Opened mail composer ({launcher}) for {args.email}")
        elif args.command == "pack":
            fmt = format_from_output_name(args.output, args.format)
            if args.no_password or fmt in ("gz", "tar.gz", "bz2", "tar.bz2", "xz", "tar.xz", "tar"):
                pw = ""
            else:
                pw = prompt_passphrase(confirm=True, allow_empty=(fmt != "klock"))
            res = pack_archive(
                args.inputs,
                args.output,
                fmt=fmt,
                passphrase=pw or None,
                keyfile_path=args.keyfile,
                algorithm=args.algo,
                level=args.level,
                encrypt_headers=args.encrypt_headers,
                zip_crypto=args.zip_crypto,
                write_checksum_file=args.write_checksum,
            )
            print(f"Packed {res['entries']} file(s) [{res['format']}] -> {res['output']} ({res['archive_size']} bytes)")
            print(f"Archive SHA-256: {res['archive_sha256']}")
            if res["checksum_file"]:
                print(f"Saved checksum:  {res['checksum_file']}")
            if args.email:
                launcher = open_email_composer(args.output, recipient=args.email)
                print(f"Opened mail composer ({launcher}) for {args.email}")
        elif args.command == "unpack":
            fmt = detect_archive_format(args.archive)
            if args.no_password or fmt in ("gz", "tar.gz", "bz2", "tar.bz2", "xz", "tar.xz", "tar"):
                pw = ""
            else:
                pw = prompt_passphrase(confirm=False, allow_empty=(fmt != "klock"))
            results, integrity = unpack_archive(
                args.archive,
                args.output,
                passphrase=pw or None,
                keyfile_path=args.keyfile,
                expected_checksum=args.checksum,
            )
            print(f"Format:          {integrity.get('format', fmt)}")
            print(f"Archive SHA-256: {integrity['archive_sha256']}")
            for path, size, ok in results:
                status = "VERIFIED" if ok else "CHECKSUM MISMATCH"
                print(f"Extracted {path} ({size} B) [{status}]")
        elif args.command == "list":
            pw = prompt_passphrase(confirm=False)
            manifest, extracted, integrity = decrypt_archive_to_memory(args.archive, pw, args.keyfile)
            print(f"Created:         {manifest.get('createdAt', 'unknown')}")
            print(f"Archive SHA-256: {integrity['archive_sha256']}")
            for entry, _, ok in extracted:
                status = "VERIFIED" if ok else "CHECKSUM MISMATCH"
                print(f"  {entry['size']:>10} B  [{status}]  {entry['path']}")
            if not integrity["all_files_ok"]:
                print("ALERT: One or more entries failed integrity verification!", file=sys.stderr)
                sys.exit(2)
        elif args.command == "verify":
            pw = prompt_passphrase(confirm=False)
            _, extracted, integrity = decrypt_archive_to_memory(
                args.archive,
                pw,
                keyfile_path=args.keyfile,
                expected_checksum=args.checksum,
            )
            print(f"Archive SHA-256: {integrity['archive_sha256']} [VERIFIED]")
            for entry, _, ok in extracted:
                print(f"  {entry['path']}: {'VERIFIED' if ok else 'INTEGRITY FAILED'}")
            if not integrity["all_files_ok"]:
                print("ALERT: File integrity check failed!", file=sys.stderr)
                sys.exit(2)
            print(f"All {len(extracted)} file(s) passed SHA-256 integrity verification.")
        elif args.command == "unlock":
            pw = prompt_passphrase(confirm=False)
            results, integrity = unlock_archive(
                args.archive,
                args.output,
                pw,
                keyfile_path=args.keyfile,
                expected_checksum=args.checksum,
            )
            print(f"Archive SHA-256: {integrity['archive_sha256']}")
            for path, size, ok in results:
                status = "VERIFIED" if ok else "CHECKSUM MISMATCH"
                print(f"Extracted {path} ({size} B) [{status}]")
    except IntegrityError as exc:
        print(f"INTEGRITY ALERT: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
`;

export const KRYPTLOCK_GUI_PY = `#!/usr/bin/env python3
"""
KryptLock Desktop GUI for Linux
Uses GTK4 + Libadwaita when available, with an automatic dark-themed Tkinter fallback.
Supports .klock, .rar (rar/unrar with & without password), .7z, .zip, .tar.gz/.gz, .tar.bz2, .tar.xz,
password strength feedback, SHA-256 integrity verification, and xdg-email attachment composing.
"""

import sys
import threading
from pathlib import Path
from typing import List, Optional

from kryptlock import (
    DEFAULT_ITERATIONS,
    IntegrityError,
    detect_available_backends,
    evaluate_password_strength,
    inspect_any_archive,
    open_email_composer,
    pack_archive,
    unpack_archive,
)

FORMAT_OPTIONS = ["klock", "rar", "7z", "zip", "tar.gz", "tar.bz2", "tar.xz", "gz"]
ALGO_OPTIONS = ["deflate", "gzip", "bzip2", "lzma", "store"]

USAGE_HELP_TEXT = """KryptLock — How to Use the Native Desktop & CLI App

1. Pack & Lock (Compress + Encrypt)
   • Click 'Add Files' (or drag files/folders) to stage items for archiving.
   • Select an output format:
     - klock   : AES-256-GCM encrypted vault with PBKDF2 + SHA-256 integrity manifest (password required).
     - rar     : RAR archive via native 'rar' CLI (password optional; supports header encryption).
     - 7z      : 7-Zip archive via '7z' CLI (optional AES-256 password + encrypted filenames).
     - zip     : ZIP archive (optional password via 7z/zip, or unencrypted).
     - tar.gz / tar.bz2 / tar.xz / gz : Standard compressed Linux tarballs (no password).
   • For .klock archives, choose an inner compression codec (deflate, gzip, bzip2, lzma, store).
   • Enter and confirm your password (watch the strength indicator; leave blank for open .rar/.7z/.zip).
   • Click 'Create Archive' to save the archive alongside a .sha256 checksum file.

2. Email Compressed / Locked Archive
   • Enter a recipient email address (optional) and click 'Email Archive'.
   • KryptLock invokes xdg-email / Thunderbird with both the archive and .sha256 file attached.

3. Unpack & Verify (Extract + Integrity Check)
   • Open the 'Unpack & Verify' tab and select any .klock, .rar, .7z, .zip, .tar.gz, .gz, .bz2, or .xz file.
   • Optionally paste a SHA-256 hex digest or path to a .sha256 file to verify before extracting.
   • Enter the password if the archive is locked (leave blank for unencrypted archives) and pick a destination folder.
   • If tampering or corruption is detected, KryptLock halts with an INTEGRITY ALERT.

4. CLI Shortcuts (Terminal)
   • kryptlock formats                 Show detected rar / unrar / 7z / zip backends
   • kryptlock guide                   Print quick command-line examples
   • kryptlock pack out.7z ./folder    Create encrypted or open 7z archive
   • kryptlock unpack out.rar -o ./out Extract RAR archive (with or without password)
"""


def format_backend_status_text() -> str:
    info = detect_available_backends()
    missing = []
    if not info.get("klock_aes_gcm"):
        missing.append("python3-cryptography")
    if not info.get("7z"):
        missing.append("p7zip-full")
    if not info.get("rar_extract"):
        missing.append("unrar")
    if not info.get("rar_create"):
        missing.append("rar")
    lines = [
        "Detected Ubuntu / Linux Backends",
        "--------------------------------",
        f"KLOCK001 (AES-256-GCM) : {'Ready' if info.get('klock_aes_gcm') else 'Missing python3-cryptography'}",
        f"RAR Create (rar)       : {info.get('rar_create') or 'Not installed'}",
        f"RAR Extract (unrar/7z) : {info.get('rar_extract') or 'Not installed'}",
        f"7-Zip (7z / 7zz)       : {info.get('7z') or 'Not installed'}",
        f"ZIP / UnZip CLI        : {info.get('zip_cli') or 'Python stdlib'} / {info.get('unzip_cli') or 'Python stdlib'}",
        f"Stdlib Codecs          : {info.get('python_stdlib')}",
    ]
    if missing:
        lines.append("")
        lines.append("To install missing optional/system packages on Ubuntu:")
        lines.append(f"sudo apt update && sudo apt install -y {' '.join(missing)} xdg-utils")
    return "\\n".join(lines)


def launch_tkinter_gui(initial_file: Optional[Path] = None) -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("KryptLock — Linux Multi-Format Archive & Lock Utility")
    root.geometry("900x700")
    root.configure(bg="#0B0F17")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background="#0B0F17")
    style.configure("TLabel", background="#0B0F17", foreground="#E2E8F0", font=("Sans", 10))
    style.configure("Header.TLabel", background="#0B0F17", foreground="#F8FAFC", font=("Sans", 14, "bold"))
    style.configure("TNotebook", background="#0B0F17", borderwidth=0)
    style.configure("TNotebook.Tab", background="#141A24", foreground="#94A3B8", padding=[16, 8])
    style.map("TNotebook.Tab", background=[("selected", "#1E293B")], foreground=[("selected", "#F8FAFC")])

    def show_tk_dialog(title: str, body: str) -> None:
        win = tk.Toplevel(root)
        win.title(title)
        win.geometry("680x480")
        win.configure(bg="#0B0F17")
        txt = tk.Text(win, wrap="word", bg="#111722", fg="#E2E8F0", relief="flat", padx=14, pady=14, font=("Monospace", 10))
        txt.pack(fill="both", expand=True, padx=14, pady=(14, 8))
        txt.insert("1.0", body)
        txt.configure(state="disabled")
        tk.Button(win, text="Close", command=win.destroy, bg="#1E293B", fg="#F8FAFC", relief="flat", padx=16, pady=6).pack(pady=(0, 12))

    menubar = tk.Menu(root, bg="#111722", fg="#E2E8F0", activebackground="#1E293B", activeforeground="#F8FAFC")
    help_menu = tk.Menu(menubar, tearoff=0, bg="#111722", fg="#E2E8F0", activebackground="#1E293B", activeforeground="#F8FAFC")
    help_menu.add_command(label="How to Use KryptLock", command=lambda: show_tk_dialog("How to Use KryptLock", USAGE_HELP_TEXT))
    help_menu.add_command(label="Check Installed Backends", command=lambda: show_tk_dialog("Detected Backends", format_backend_status_text()))
    help_menu.add_separator()
    help_menu.add_command(
        label="About KryptLock",
        command=lambda: messagebox.showinfo(
            "About KryptLock",
            "KryptLock 1.0.0\\nLinux Multi-Format Compression & AES-256-GCM Archive Tool\\nSupports .klock, .rar, .7z, .zip, .tar.gz, .tar.bz2, and .tar.xz.",
        ),
    )
    menubar.add_cascade(label="Help", menu=help_menu)
    root.config(menu=menubar)

    header = ttk.Frame(root, padding=16)
    header.pack(fill="x")
    ttk.Label(header, text="KryptLock", style="Header.TLabel").pack(side="left")
    tk.Button(
        header,
        text="Help & Guide",
        command=lambda: show_tk_dialog("How to Use KryptLock", USAGE_HELP_TEXT),
        bg="#1E293B",
        fg="#F8FAFC",
        relief="flat",
        padx=10,
        pady=4,
    ).pack(side="right", padx=(10, 0))
    ttk.Label(
        header,
        text="KLOCK · RAR / UnRAR · 7z · ZIP · Gzip / Bzip2 / XZ · SHA-256",
        foreground="#94A3B8",
    ).pack(side="right")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    # --- Pack & Lock Tab ---
    lock_tab = ttk.Frame(notebook, padding=16)
    notebook.add(lock_tab, text="Pack & Lock")

    staged_paths: List[Path] = []
    listbox = tk.Listbox(
        lock_tab,
        bg="#141A24",
        fg="#E2E8F0",
        selectbackground="#10B981",
        relief="flat",
        highlightthickness=1,
        highlightbackground="#283244",
        height=8,
    )
    listbox.pack(fill="both", expand=True, pady=(0, 10))

    def add_files() -> None:
        files = filedialog.askopenfilenames(title="Select files to pack")
        for f in files:
            p = Path(f)
            if p not in staged_paths:
                staged_paths.append(p)
                listbox.insert("end", str(p))

    def add_folder() -> None:
        folder = filedialog.askdirectory(title="Select folder to pack")
        if folder:
            p = Path(folder)
            if p not in staged_paths:
                staged_paths.append(p)
                listbox.insert("end", f"[DIR] {p}")

    def clear_staged() -> None:
        staged_paths.clear()
        listbox.delete(0, "end")

    btn_row = ttk.Frame(lock_tab)
    btn_row.pack(fill="x", pady=(0, 10))
    tk.Button(btn_row, text="Add Files", command=add_files, bg="#1E293B", fg="#F8FAFC", relief="flat", padx=12, pady=6).pack(side="left", padx=(0, 8))
    tk.Button(btn_row, text="Add Folder", command=add_folder, bg="#1E293B", fg="#F8FAFC", relief="flat", padx=12, pady=6).pack(side="left", padx=(0, 8))
    tk.Button(btn_row, text="Clear List", command=clear_staged, bg="#1E293B", fg="#94A3B8", relief="flat", padx=12, pady=6).pack(side="left")

    fmt_row = ttk.Frame(lock_tab)
    fmt_row.pack(fill="x", pady=(0, 10))
    ttk.Label(fmt_row, text="Archive Format:").pack(side="left", padx=(0, 8))
    fmt_var = tk.StringVar(value="klock")
    ttk.Combobox(fmt_row, textvariable=fmt_var, values=FORMAT_OPTIONS, state="readonly", width=10).pack(side="left", padx=(0, 16))
    ttk.Label(fmt_row, text=".klock Codec:").pack(side="left", padx=(0, 8))
    algo_var = tk.StringVar(value="deflate")
    ttk.Combobox(fmt_row, textvariable=algo_var, values=ALGO_OPTIONS, state="readonly", width=10).pack(side="left", padx=(0, 16))
    ttk.Label(fmt_row, text="Level (1-9):").pack(side="left", padx=(0, 8))
    level_var = tk.IntVar(value=6)
    ttk.Spinbox(fmt_row, from_=1, to=9, textvariable=level_var, width=5).pack(side="left")

    pw_frame = ttk.Frame(lock_tab)
    pw_frame.pack(fill="x", pady=(0, 6))
    ttk.Label(pw_frame, text="Password (optional):", width=18).pack(side="left")
    lock_pw_var = tk.StringVar()
    tk.Entry(pw_frame, textvariable=lock_pw_var, show="*", bg="#141A24", fg="#F8FAFC", insertbackground="#F8FAFC", relief="flat").pack(side="left", fill="x", expand=True)

    pw2_frame = ttk.Frame(lock_tab)
    pw2_frame.pack(fill="x", pady=(0, 6))
    ttk.Label(pw2_frame, text="Confirm Password:", width=18).pack(side="left")
    lock_pw2_var = tk.StringVar()
    tk.Entry(pw2_frame, textvariable=lock_pw2_var, show="*", bg="#141A24", fg="#F8FAFC", insertbackground="#F8FAFC", relief="flat").pack(side="left", fill="x", expand=True)

    strength_label = tk.Label(
        lock_tab,
        text="Strength: Empty (0 bits) · Leave blank for unencrypted .rar/.7z/.zip/.tar.gz",
        bg="#0B0F17",
        fg="#94A3B8",
        anchor="w",
        font=("Sans", 9),
    )
    strength_label.pack(fill="x", pady=(0, 8))

    def on_pw_change(*_args: object) -> None:
        pw = lock_pw_var.get()
        if not pw:
            strength_label.config(text="Strength: Empty · Leave blank for unencrypted .rar/.7z/.zip/.tar.*", fg="#94A3B8")
            return
        s = evaluate_password_strength(pw)
        colors = {0: "#94A3B8", 1: "#F87171", 2: "#FBBF24", 3: "#34D399", 4: "#10B981"}
        hint = f" · {s['hints'][0]}" if s["hints"] else ""
        strength_label.config(text=f"Password Strength: {s['label']} ({s['bits']} bits){hint}", fg=colors[s["score"]])

    lock_pw_var.trace_add("write", on_pw_change)

    opts_row = ttk.Frame(lock_tab)
    opts_row.pack(fill="x", pady=(0, 8))
    encrypt_headers_var = tk.BooleanVar(value=True)
    tk.Checkbutton(
        opts_row,
        text="Encrypt filenames/headers (.rar -hp / .7z -mhe)",
        variable=encrypt_headers_var,
        bg="#0B0F17",
        fg="#CBD5E1",
        selectcolor="#141A24",
        activebackground="#0B0F17",
        activeforeground="#F8FAFC",
    ).pack(side="left", padx=(0, 16))
    write_sha_var = tk.BooleanVar(value=True)
    tk.Checkbutton(
        opts_row,
        text="Write .sha256 sidecar",
        variable=write_sha_var,
        bg="#0B0F17",
        fg="#CBD5E1",
        selectcolor="#141A24",
        activebackground="#0B0F17",
        activeforeground="#F8FAFC",
    ).pack(side="left")

    last_locked_archive: Optional[Path] = None

    email_row = ttk.Frame(lock_tab)
    email_row.pack(fill="x", pady=(0, 8))
    ttk.Label(email_row, text="Email Recipient:", width=18).pack(side="left")
    email_to_var = tk.StringVar()
    tk.Entry(email_row, textvariable=email_to_var, bg="#141A24", fg="#F8FAFC", insertbackground="#F8FAFC", relief="flat").pack(side="left", fill="x", expand=True)

    def do_email_locked() -> None:
        nonlocal last_locked_archive
        target = last_locked_archive
        if target is None or not target.is_file():
            picked = filedialog.askopenfilename(title="Select archive to email")
            if not picked:
                return
            target = Path(picked)
        try:
            launcher = open_email_composer(target, recipient=email_to_var.get().strip())
            messagebox.showinfo("KryptLock Email", f"Opened Linux mail client ({launcher}) with {target.name} attached.")
        except Exception as err:
            messagebox.showerror("Email Launch Failed", str(err))

    def do_pack() -> None:
        nonlocal last_locked_archive
        if not staged_paths:
            messagebox.showwarning("KryptLock", "Add at least one file or folder first.")
            return
        fmt = fmt_var.get()
        pw = lock_pw_var.get()
        if fmt == "klock" and not pw:
            messagebox.showwarning("KryptLock", "Enter a password for .klock AES-256-GCM encryption.")
            return
        if pw and pw != lock_pw2_var.get():
            messagebox.showerror("KryptLock", "Passwords do not match.")
            return
        out = filedialog.asksaveasfilename(
            title=f"Save .{fmt} archive",
            defaultextension=f".{fmt}",
            filetypes=[("Archive", f"*.{fmt}"), ("All files", "*.*")],
        )
        if not out:
            return

        def worker() -> None:
            nonlocal last_locked_archive
            try:
                out_path = Path(out)
                res = pack_archive(
                    staged_paths,
                    out_path,
                    fmt=fmt,
                    passphrase=pw or None,
                    algorithm=algo_var.get(),
                    level=level_var.get(),
                    iterations=DEFAULT_ITERATIONS,
                    encrypt_headers=encrypt_headers_var.get(),
                    write_checksum_file=write_sha_var.get(),
                )
                last_locked_archive = out_path
                msg = (
                    f"Created {out_path.name} ({res['format']}, {res['entries']} file(s)).\\n"
                    f"Archive SHA-256:\\n{res['archive_sha256']}"
                )
                root.after(0, lambda: messagebox.showinfo("Archive Created & Checksummed", msg))
            except Exception as err:
                root.after(0, lambda: messagebox.showerror("Pack Failed", str(err)))

        threading.Thread(target=worker, daemon=True).start()

    lock_actions = ttk.Frame(lock_tab)
    lock_actions.pack(fill="x")
    tk.Button(lock_actions, text="Email Archive", command=do_email_locked, bg="#1E293B", fg="#F8FAFC", relief="flat", padx=14, pady=8).pack(side="left")
    tk.Button(lock_actions, text="Create Archive", command=do_pack, bg="#10B981", fg="#052E16", font=("Sans", 10, "bold"), relief="flat", padx=16, pady=8).pack(side="right")

    # --- Unlock / Extract Tab ---
    unlock_tab = ttk.Frame(notebook, padding=16)
    notebook.add(unlock_tab, text="Unpack & Verify")

    archive_var = tk.StringVar(value=str(initial_file) if initial_file else "")
    row1 = ttk.Frame(unlock_tab)
    row1.pack(fill="x", pady=(0, 8))
    ttk.Label(row1, text="Archive File:", width=18).pack(side="left")
    tk.Entry(row1, textvariable=archive_var, bg="#141A24", fg="#F8FAFC", insertbackground="#F8FAFC", relief="flat").pack(side="left", fill="x", expand=True, padx=(0, 8))

    def browse_archive() -> None:
        path = filedialog.askopenfilename(
            title="Open archive (.klock, .rar, .7z, .zip, .gz, .bz2, .xz, .tar)",
            filetypes=[
                ("Supported Archives", "*.klock *.rar *.7z *.zip *.gz *.tgz *.bz2 *.tbz2 *.xz *.txz *.tar"),
                ("All files", "*.*"),
            ],
        )
        if path:
            archive_var.set(path)

    tk.Button(row1, text="Browse", command=browse_archive, bg="#1E293B", fg="#F8FAFC", relief="flat", padx=12, pady=6).pack(side="right")

    row_sha = ttk.Frame(unlock_tab)
    row_sha.pack(fill="x", pady=(0, 8))
    ttk.Label(row_sha, text="Expected SHA-256:", width=18).pack(side="left")
    expected_sha_var = tk.StringVar()
    tk.Entry(row_sha, textvariable=expected_sha_var, bg="#141A24", fg="#F8FAFC", insertbackground="#F8FAFC", relief="flat").pack(side="left", fill="x", expand=True)

    row2 = ttk.Frame(unlock_tab)
    row2.pack(fill="x", pady=(0, 10))
    ttk.Label(row2, text="Password (if locked):", width=18).pack(side="left")
    unlock_pw_var = tk.StringVar()
    tk.Entry(row2, textvariable=unlock_pw_var, show="*", bg="#141A24", fg="#F8FAFC", insertbackground="#F8FAFC", relief="flat").pack(side="left", fill="x", expand=True)

    output_box = tk.Text(
        unlock_tab,
        bg="#141A24",
        fg="#CBD5E1",
        relief="flat",
        highlightthickness=1,
        highlightbackground="#283244",
        height=12,
    )
    output_box.pack(fill="both", expand=True, pady=(0, 12))

    def do_inspect() -> None:
        p = Path(archive_var.get().strip())
        if not p.is_file():
            messagebox.showwarning("KryptLock", "Select a valid archive file first.")
            return
        try:
            info = inspect_any_archive(p)
            output_box.delete("1.0", "end")
            output_box.insert("end", f"Format:          {info['format']}\\n")
            output_box.insert("end", f"Magic:           {info['magic']}\\n")
            output_box.insert("end", f"Archive SHA-256: {info['archive_sha256']}\\n")
            output_box.insert("end", f"Total Size:      {info['total_bytes']:,} bytes\\n")
            if "iterations" in info:
                output_box.insert("end", f"PBKDF2 Rounds:   {info['iterations']:,}\\n")
        except Exception as err:
            messagebox.showerror("Inspection Error", str(err))

    def do_extract() -> None:
        p = Path(archive_var.get().strip())
        pw = unlock_pw_var.get()
        if not p.is_file():
            messagebox.showwarning("KryptLock", "Select a valid archive file first.")
            return
        dest = filedialog.askdirectory(title="Choose extraction folder")
        if not dest:
            return
        expected_sha = expected_sha_var.get().strip() or None

        def worker() -> None:
            try:
                results, integrity = unpack_archive(p, Path(dest), passphrase=pw or None, expected_checksum=expected_sha)
                lines = [
                    f"Format:          {integrity.get('format', 'archive')}",
                    f"Archive SHA-256: {integrity['archive_sha256']} [VERIFIED]",
                    "",
                ]
                lines.extend(
                    f"{name} ({size} B) — {'VERIFIED' if ok else 'CHECKSUM MISMATCH'}"
                    for name, size, ok in results
                )
                summary = "\\n".join(lines)
                root.after(0, lambda: (output_box.delete("1.0", "end"), output_box.insert("end", summary)))
            except IntegrityError as err:
                root.after(0, lambda: messagebox.showerror("INTEGRITY CHECK FAILED", str(err)))
            except Exception as err:
                root.after(0, lambda: messagebox.showerror("Extract Failed", str(err)))

        threading.Thread(target=worker, daemon=True).start()

    act_row = ttk.Frame(unlock_tab)
    act_row.pack(fill="x")
    tk.Button(act_row, text="Inspect Format & SHA-256", command=do_inspect, bg="#1E293B", fg="#F8FAFC", relief="flat", padx=14, pady=8).pack(side="left")
    tk.Button(act_row, text="Unpack / Unlock & Extract", command=do_extract, bg="#10B981", fg="#052E16", font=("Sans", 10, "bold"), relief="flat", padx=16, pady=8).pack(side="right")

    # --- Help & Guide Tab ---
    help_tab = ttk.Frame(notebook, padding=16)
    notebook.add(help_tab, text="Help & Guide")
    help_text_widget = tk.Text(help_tab, wrap="word", bg="#111722", fg="#E2E8F0", relief="flat", padx=14, pady=14, font=("Monospace", 10))
    help_text_widget.pack(fill="both", expand=True, pady=(0, 10))
    help_text_widget.insert("1.0", f"{USAGE_HELP_TEXT}\\n{format_backend_status_text()}")
    help_text_widget.configure(state="disabled")

    def refresh_help_backends() -> None:
        help_text_widget.configure(state="normal")
        help_text_widget.delete("1.0", "end")
        help_text_widget.insert("1.0", f"{USAGE_HELP_TEXT}\\n{format_backend_status_text()}")
        help_text_widget.configure(state="disabled")

    tk.Button(help_tab, text="Refresh Detected Backends", command=refresh_help_backends, bg="#1E293B", fg="#F8FAFC", relief="flat", padx=14, pady=8).pack(side="left")

    if initial_file:
        notebook.select(unlock_tab)
        do_inspect()

    root.mainloop()


def main() -> None:
    initial = Path(sys.argv[1]) if len(sys.argv) > 1 and Path(sys.argv[1]).is_file() else None
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gio, Gtk

        class KryptLockWindow(Adw.ApplicationWindow):
            def __init__(self, app: Adw.Application) -> None:
                super().__init__(application=app, title="KryptLock", default_width=820, default_height=640)
                self.staged_files: List[Path] = []

                toolbar = Adw.ToolbarView()
                header = Adw.HeaderBar()
                switcher = Adw.ViewSwitcher()
                stack = Adw.ViewStack()
                switcher.set_stack(stack)
                header.set_title_widget(switcher)

                help_menu_model = Gio.Menu()
                help_menu_model.append("How to Use KryptLock", "win.help-usage")
                help_menu_model.append("Check Installed Backends", "win.help-backends")
                help_menu_model.append("About KryptLock", "win.about")

                help_btn = Gtk.MenuButton(label="Help", menu_model=help_menu_model)
                help_btn.set_tooltip_text("How to Use & Diagnostics (F1)")
                header.pack_end(help_btn)

                for action_name, cb in (
                    ("help-usage", lambda _a, _p: self._show_text_dialog("How to Use KryptLock", USAGE_HELP_TEXT)),
                    ("help-backends", lambda _a, _p: self._show_text_dialog("Detected Ubuntu / Linux Backends", format_backend_status_text())),
                    (
                        "about",
                        lambda _a, _p: self._show_text_dialog(
                            "About KryptLock",
                            "KryptLock 1.0.0\\n"
                            "Native Ubuntu & Linux Multi-Format Compression and Encryption Utility\\n\\n"
                            "Formats: .klock (AES-256-GCM), .rar / UnRAR, .7z, .zip, .tar.gz, .tar.bz2, .tar.xz\\n"
                            "Integrates SHA-256 integrity verification and xdg-email attachment composing.",
                        ),
                    ),
                ):
                    act = Gio.SimpleAction.new(action_name, None)
                    act.connect("activate", cb)
                    self.add_action(act)

                toolbar.add_top_bar(header)

                # Pack & Lock page
                lock_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
                lock_box.set_margin_top(20)
                lock_box.set_margin_bottom(20)
                lock_box.set_margin_start(20)
                lock_box.set_margin_end(20)

                self.list_box = Gtk.ListBox()
                self.list_box.add_css_class("boxed-list")
                scrolled = Gtk.ScrolledWindow(vexpand=True)
                scrolled.set_child(self.list_box)
                lock_box.append(scrolled)

                controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                add_btn = Gtk.Button(label="Add Files")
                add_btn.connect("clicked", self.on_add_files)
                clear_btn = Gtk.Button(label="Clear")
                clear_btn.connect("clicked", self.on_clear)
                self.fmt_dropdown = Gtk.DropDown.new_from_strings(FORMAT_OPTIONS)
                self.algo_dropdown = Gtk.DropDown.new_from_strings(ALGO_OPTIONS)
                controls.append(add_btn)
                controls.append(clear_btn)
                controls.append(self.fmt_dropdown)
                controls.append(self.algo_dropdown)
                lock_box.append(controls)

                self.lock_pw = Gtk.PasswordEntry(placeholder_text="Password (optional for .rar/.7z/.zip)", show_peek_icon=True)
                self.lock_pw.connect("changed", self.on_password_changed)
                lock_box.append(self.lock_pw)

                self.lock_pw_confirm = Gtk.PasswordEntry(placeholder_text="Confirm password", show_peek_icon=True)
                lock_box.append(self.lock_pw_confirm)

                self.strength_label = Gtk.Label(label="Password Strength: Empty · Leave blank for unencrypted .rar/.7z/.zip", xalign=0)
                lock_box.append(self.strength_label)

                self.last_locked_path: Optional[Path] = None

                self.email_entry = Gtk.Entry(placeholder_text="Recipient email (optional, e.g. alice@example.com)")
                lock_box.append(self.email_entry)

                self.lock_status = Gtk.Label(label="", wrap=True, xalign=0)
                lock_box.append(self.lock_status)

                action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                lock_btn = Gtk.Button(label="Create Archive")
                lock_btn.add_css_class("suggested-action")
                lock_btn.connect("clicked", self.on_pack_archive)
                email_btn = Gtk.Button(label="Email Archive")
                email_btn.connect("clicked", self.on_email_locked)
                action_box.append(lock_btn)
                action_box.append(email_btn)
                lock_box.append(action_box)

                stack.add_titled_with_icon(lock_box, "lock", "Pack & Lock", "changes-prevent-symbolic")

                # Unpack page
                unlock_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
                unlock_box.set_margin_top(20)
                unlock_box.set_margin_bottom(20)
                unlock_box.set_margin_start(20)
                unlock_box.set_margin_end(20)

                self.archive_entry = Gtk.Entry(placeholder_text="Path to .klock, .rar, .7z, .zip, .tar.gz, .gz, .bz2, or .xz archive")
                if initial:
                    self.archive_entry.set_text(str(initial))
                unlock_box.append(self.archive_entry)

                self.checksum_entry = Gtk.Entry(placeholder_text="Optional expected SHA-256 hex or .sha256 file")
                unlock_box.append(self.checksum_entry)

                self.unlock_pw = Gtk.PasswordEntry(placeholder_text="Password (leave blank if archive is unencrypted)", show_peek_icon=True)
                unlock_box.append(self.unlock_pw)

                self.status_label = Gtk.Label(label="Select any archive (.klock, .rar, .7z, .zip, .gz, .bz2, .xz) to unpack.", wrap=True, xalign=0)
                unlock_box.append(self.status_label)

                unlock_btn = Gtk.Button(label="Unpack / Unlock & Extract")
                unlock_btn.add_css_class("suggested-action")
                unlock_btn.connect("clicked", self.on_unpack_archive)
                unlock_box.append(unlock_btn)

                stack.add_titled_with_icon(unlock_box, "unlock", "Unpack & Verify", "changes-allow-symbolic")

                # Help & Guide page
                help_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
                help_box.set_margin_top(20)
                help_box.set_margin_bottom(20)
                help_box.set_margin_start(20)
                help_box.set_margin_end(20)

                self.help_view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
                self.help_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
                self.help_view.get_buffer().set_text(f"{USAGE_HELP_TEXT}\\n{format_backend_status_text()}")
                help_scroll = Gtk.ScrolledWindow(vexpand=True)
                help_scroll.set_child(self.help_view)
                help_box.append(help_scroll)

                refresh_btn = Gtk.Button(label="Refresh Detected Backends")
                refresh_btn.connect("clicked", self.on_refresh_help_backends)
                help_box.append(refresh_btn)

                stack.add_titled_with_icon(help_box, "help", "Help", "help-about-symbolic")

                if initial:
                    stack.set_visible_child_name("unlock")

                toolbar.set_content(stack)
                self.set_content(toolbar)

            def on_refresh_help_backends(self, _btn: Gtk.Button) -> None:
                self.help_view.get_buffer().set_text(f"{USAGE_HELP_TEXT}\\n{format_backend_status_text()}")

            def _show_text_dialog(self, title: str, body: str) -> None:
                dlg = Gtk.Window(title=title, transient_for=self, modal=True, default_width=680, default_height=480)
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
                box.set_margin_top(16)
                box.set_margin_bottom(16)
                box.set_margin_start(16)
                box.set_margin_end(16)

                tv = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
                tv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
                tv.get_buffer().set_text(body)
                sc = Gtk.ScrolledWindow(vexpand=True)
                sc.set_child(tv)
                box.append(sc)

                close_btn = Gtk.Button(label="Close")
                close_btn.connect("clicked", lambda _b: dlg.close())
                box.append(close_btn)

                dlg.set_child(box)
                dlg.present()

            def on_password_changed(self, _entry: Gtk.PasswordEntry) -> None:
                pw = self.lock_pw.get_text()
                if not pw:
                    self.strength_label.set_text("Password Strength: Empty · Leave blank for unencrypted .rar/.7z/.zip")
                    return
                s = evaluate_password_strength(pw)
                hint = f" — {s['hints'][0]}" if s["hints"] else ""
                self.strength_label.set_text(f"Password Strength: {s['label']} ({s['bits']} bits){hint}")

            def on_add_files(self, _btn: Gtk.Button) -> None:
                dialog = Gtk.FileDialog()
                dialog.open_multiple(self, None, self._on_files_picked)

            def _on_files_picked(self, dialog: Gtk.FileDialog, res: Gio.AsyncResult) -> None:
                try:
                    files = dialog.open_multiple_finish(res)
                    for i in range(files.get_n_items()):
                        f = files.get_item(i)
                        p = Path(f.get_path())
                        if p not in self.staged_files:
                            self.staged_files.append(p)
                            row = Adw.ActionRow(title=p.name, subtitle=str(p.parent))
                            self.list_box.append(row)
                except Exception:
                    pass

            def on_clear(self, _btn: Gtk.Button) -> None:
                self.staged_files.clear()
                while child := self.list_box.get_first_child():
                    self.list_box.remove(child)

            def on_pack_archive(self, _btn: Gtk.Button) -> None:
                fmt = FORMAT_OPTIONS[self.fmt_dropdown.get_selected()]
                pw = self.lock_pw.get_text()
                pw2 = self.lock_pw_confirm.get_text()
                if not self.staged_files:
                    self.lock_status.set_text("Stage files first.")
                    return
                if fmt == "klock" and not pw:
                    self.lock_status.set_text("Enter a password for .klock AES-256-GCM encryption.")
                    return
                if pw and pw != pw2:
                    self.lock_status.set_text("Error: Passwords do not match.")
                    return
                algo = ALGO_OPTIONS[self.algo_dropdown.get_selected()]
                dialog = Gtk.FileDialog(initial_name=f"archive.{fmt}")
                dialog.save(self, None, lambda d, r: self._finish_save(d, r, fmt, pw, algo))

            def _finish_save(self, dialog: Gtk.FileDialog, res: Gio.AsyncResult, fmt: str, pw: str, algo: str) -> None:
                try:
                    f = dialog.save_finish(res)
                    out_path = Path(f.get_path())
                    info = pack_archive(
                        self.staged_files,
                        out_path,
                        fmt=fmt,
                        passphrase=pw or None,
                        algorithm=algo,
                        write_checksum_file=True,
                    )
                    self.last_locked_path = out_path
                    self.lock_status.set_text(f"Created {out_path.name} ({fmt}). SHA-256: {info['archive_sha256']}")
                except Exception as exc:
                    self.lock_status.set_text(f"Pack error: {exc}")

            def on_email_locked(self, _btn: Gtk.Button) -> None:
                if self.last_locked_path and self.last_locked_path.is_file():
                    self._launch_email(self.last_locked_path)
                    return
                dialog = Gtk.FileDialog()
                dialog.open(self, None, self._on_email_file_picked)

            def _on_email_file_picked(self, dialog: Gtk.FileDialog, res: Gio.AsyncResult) -> None:
                try:
                    f = dialog.open_finish(res)
                    self._launch_email(Path(f.get_path()))
                except Exception:
                    pass

            def _launch_email(self, archive_path: Path) -> None:
                try:
                    launcher = open_email_composer(archive_path, recipient=self.email_entry.get_text().strip())
                    self.lock_status.set_text(f"Opened mail client ({launcher}) with {archive_path.name} attached.")
                except Exception as exc:
                    self.lock_status.set_text(f"Email error: {exc}")

            def on_unpack_archive(self, _btn: Gtk.Button) -> None:
                archive = Path(self.archive_entry.get_text().strip())
                pw = self.unlock_pw.get_text()
                if not archive.is_file():
                    self.status_label.set_text("Provide a valid archive file path.")
                    return
                expected_sha = self.checksum_entry.get_text().strip() or None
                dialog = Gtk.FileDialog()
                dialog.select_folder(self, None, lambda d, r: self._finish_extract(d, r, archive, pw, expected_sha))

            def _finish_extract(self, dialog: Gtk.FileDialog, res: Gio.AsyncResult, archive: Path, pw: str, expected_sha: Optional[str]) -> None:
                try:
                    folder = dialog.select_folder_finish(res)
                    extracted, integrity = unpack_archive(archive, Path(folder.get_path()), passphrase=pw or None, expected_checksum=expected_sha)
                    self.status_label.set_text(
                        f"Extracted {len(extracted)} file(s) [{integrity.get('format')}]. Archive SHA-256: {integrity['archive_sha256']}"
                    )
                except IntegrityError as exc:
                    self.status_label.set_text(f"INTEGRITY ALERT: {exc}")
                except Exception as exc:
                    self.status_label.set_text(f"Extract error: {exc}")

        class KryptLockApp(Adw.Application):
            def __init__(self) -> None:
                super().__init__(application_id="org.kryptlock.ArchiveTool")

            def do_activate(self) -> None:
                self.set_accels_for_action("win.help-usage", ["F1"])
                win = KryptLockWindow(self)
                win.present()

        app = KryptLockApp()
        app.run(None)
    except Exception:
        launch_tkinter_gui(initial)


if __name__ == "__main__":
    main()
`;

export const KRYPTLOCK_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <rect width="128" height="128" rx="28" fill="#0B0F17"/>
  <rect x="6" y="6" width="116" height="116" rx="22" fill="#111722" stroke="#1E293B" stroke-width="2"/>
  <path d="M64 20L98 34V62C98 84 83.5 101.8 64 109C44.5 101.8 30 84 30 62V34L64 20Z" fill="#0F172A" stroke="#10B981" stroke-width="4" stroke-linejoin="round"/>
  <rect x="46" y="57" width="36" height="28" rx="6" fill="#10B981"/>
  <path d="M53 57V49C53 42.9 57.9 38 64 38C70.1 38 75 42.9 75 49V57" fill="none" stroke="#10B981" stroke-width="5" stroke-linecap="round"/>
  <circle cx="64" cy="69" r="4" fill="#0B0F17"/>
  <rect x="62" y="71" width="4" height="8" rx="2" fill="#0B0F17"/>
</svg>
`;

export const KRYPTLOCK_DESKTOP_TEMPLATE = `[Desktop Entry]
Name=KryptLock
Comment=Compress, RAR/UnRAR, 7z, ZIP, Gzip, Bzip2, XZ, and AES-256-GCM lock archives
Exec=/usr/bin/kryptlock-gui %f
Icon=kryptlock
StartupWMClass=org.kryptlock.ArchiveTool
Terminal=false
Type=Application
Categories=Utility;Security;Archiving;
MimeType=application/x-kryptlock;application/vnd.rar;application/x-rar-compressed;application/x-7z-compressed;application/zip;application/gzip;application/x-bzip2;application/x-xz;
Keywords=encrypt;decrypt;rar;unrar;7z;7zip;zip;gzip;bzip2;xz;archive;compress;lock;
`;

export const KRYPTLOCK_MIME_XML = `<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-kryptlock">
    <comment>KryptLock Encrypted Archive</comment>
    <glob pattern="*.klock"/>
    <magic priority="60">
      <match type="string" value="KLOCK001" offset="0"/>
    </magic>
  </mime-type>
</mime-info>
`;

export const DEB_CONTROL_TEMPLATE = `Package: kryptlock
Version: 1.0.0
Section: utils
Priority: optional
Architecture: all
Maintainer: KryptLock <rpkirchin@gmail.com>
Depends: python3 (>= 3.9), python3-cryptography, python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1, python3-tk, p7zip-full, xdg-utils
Recommends: unrar | unar, rar, zenity
Description: Multi-format Linux compression and encrypted archive utility
 KryptLock packs, locks, verifies, and extracts .klock (AES-256-GCM),
 .rar (via rar/unrar), .7z, .zip, .tar.gz, .tar.bz2, and .tar.xz archives
 with a native GTK4/Libadwaita desktop GUI, CLI, and SHA-256 verification.
`;

export const DEB_POSTINST = `#!/bin/sh
set -e
if command -v update-mime-database >/dev/null 2>&1; then
  update-mime-database /usr/share/mime || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
`;

export const DEB_POSTRM = `#!/bin/sh
set -e
if command -v update-mime-database >/dev/null 2>&1; then
  update-mime-database /usr/share/mime || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications || true
fi
exit 0
`;

const NAUTILUS_SCRIPT_SH = `#!/usr/bin/env bash
# Right-click "Scripts -> Lock with KryptLock" for GNOME Files (Nautilus) / Nemo
set -euo pipefail

if [ "$#" -eq 0 ]; then
  exit 0
fi

OUT_NAME="$(basename "$1").klock"
if command -v zenity >/dev/null 2>&1; then
  FMT="$(zenity --list --title="KryptLock — Select Format" --column="Format" klock rar 7z zip tar.gz tar.bz2 tar.xz || echo klock)"
  OUT_NAME="$(basename "$1").\${FMT}"
  PASS="$(zenity --password --title="KryptLock — Password (optional except .klock)")"
  OUT_PATH="$(zenity --file-selection --save --confirm-overwrite --filename="$PWD/$OUT_NAME")"
  python3 -c '
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / ".local/share/kryptlock"))
from kryptlock import pack_archive
res = pack_archive([Path(p) for p in sys.argv[4:]], Path(sys.argv[1]), fmt=sys.argv[3], passphrase=sys.argv[2] or None, write_checksum_file=True)
print(res["archive_sha256"])
' "$OUT_PATH" "$PASS" "$FMT" "$@"
  zenity --info --text="Archive created: $OUT_PATH (with .sha256 checksum)"
else
  if command -v kryptlock-gui >/dev/null 2>&1; then
    exec kryptlock-gui "$1"
  elif [ -x "/usr/bin/kryptlock-gui" ]; then
    exec /usr/bin/kryptlock-gui "$1"
  else
    exec "\${HOME}/.local/bin/kryptlock-gui" "$1"
  fi
fi
`;

const INSTALL_SH = `#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="\${HOME}/.local/share/kryptlock"
BIN_DIR="\${HOME}/.local/bin"
DESKTOP_DIR="\${HOME}/.local/share/applications"
MIME_DIR="\${HOME}/.local/share/mime/packages"
ICON_DIR="\${HOME}/.local/share/icons/hicolor/scalable/apps"
NAUTILUS_DIR="\${HOME}/.local/share/nautilus/scripts"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required. Install it first: sudo apt install -y python3" >&2
  exit 1
fi

echo "Installing KryptLock from \${SCRIPT_DIR} into \${APP_DIR}..."
mkdir -p "\${APP_DIR}" "\${BIN_DIR}" "\${DESKTOP_DIR}" "\${MIME_DIR}" "\${ICON_DIR}" "\${NAUTILUS_DIR}"

cp "\${SCRIPT_DIR}/kryptlock.py" "\${SCRIPT_DIR}/kryptlock_gui.py" "\${APP_DIR}/"
chmod +x "\${APP_DIR}/kryptlock.py" "\${APP_DIR}/kryptlock_gui.py"

cat > "\${BIN_DIR}/kryptlock" <<EOF
#!/usr/bin/env bash
PYTHONPATH="\${APP_DIR}" exec python3 "\${APP_DIR}/kryptlock.py" "\\$@"
EOF
chmod +x "\${BIN_DIR}/kryptlock"

cat > "\${BIN_DIR}/kryptlock-gui" <<EOF
#!/usr/bin/env bash
PYTHONPATH="\${APP_DIR}" exec python3 "\${APP_DIR}/kryptlock_gui.py" "\\$@"
EOF
chmod +x "\${BIN_DIR}/kryptlock-gui"

if [ -f "\${SCRIPT_DIR}/kryptlock.svg" ]; then
  cp "\${SCRIPT_DIR}/kryptlock.svg" "\${ICON_DIR}/kryptlock.svg"
fi

# Write desktop entry with an absolute Exec path so GNOME/Ubuntu launches it reliably
sed "s|^Exec=.*|Exec=\${BIN_DIR}/kryptlock-gui %f|" "\${SCRIPT_DIR}/kryptlock.desktop" > "\${DESKTOP_DIR}/kryptlock.desktop"
cp "\${SCRIPT_DIR}/kryptlock-mime.xml" "\${MIME_DIR}/kryptlock-mime.xml"
cp "\${SCRIPT_DIR}/nautilus-script.sh" "\${NAUTILUS_DIR}/Lock with KryptLock"
chmod +x "\${NAUTILUS_DIR}/Lock with KryptLock"

if command -v update-mime-database >/dev/null 2>&1; then
  update-mime-database "\${HOME}/.local/share/mime" || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "\${DESKTOP_DIR}" || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f "\${HOME}/.local/share/icons/hicolor" || true
fi

# Ensure ~/.local/bin is in PATH for future terminals
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
for rc in "\${HOME}/.bashrc" "\${HOME}/.profile"; do
  if [ -f "\${rc}" ] && ! grep -q '\\.local/bin' "\${rc}"; then
    printf '\\n# Added by KryptLock installer\\n%s\\n' "\${PATH_LINE}" >> "\${rc}"
  fi
done

echo ""
echo "Checking Python & archive dependencies..."
MISSING_APT=()
python3 -c "import cryptography" >/dev/null 2>&1 || MISSING_APT+=("python3-cryptography")
python3 -c "import gi; gi.require_version('Gtk', '4.0'); gi.require_version('Adw', '1')" >/dev/null 2>&1 || MISSING_APT+=("python3-gi" "gir1.2-gtk-4.0" "gir1.2-adw-1")
command -v 7z >/dev/null 2>&1 || command -v 7zz >/dev/null 2>&1 || MISSING_APT+=("p7zip-full")
command -v unrar >/dev/null 2>&1 || command -v unar >/dev/null 2>&1 || MISSING_APT+=("unrar")

if [ \${#MISSING_APT[@]} -gt 0 ]; then
  echo "Notice: Optional or required Ubuntu packages not detected: \${MISSING_APT[*]}"
  echo "Run: sudo apt update && sudo apt install -y \${MISSING_APT[*]} xdg-utils"
fi

echo ""
echo "KryptLock installed successfully!"
echo "CLI binary: \${BIN_DIR}/kryptlock"
echo "GUI binary: \${BIN_DIR}/kryptlock-gui"
echo ""
"\${BIN_DIR}/kryptlock" formats || true
echo ""
echo "Open a new terminal (or run: export PATH=\\"\\$HOME/.local/bin:\\$PATH\\") and launch with: kryptlock-gui"
`;

const README_MD = `# KryptLock — Linux Multi-Format Compression & Encrypted Archive Utility

KryptLock packs, locks, verifies, and extracts **\`.klock\` (AES-256-GCM)**, **\`.rar\` (RAR & UnRAR with or without passwords)**, **\`.7z\` (with or without AES-256 + header encryption)**, **\`.zip\` (with or without AES-256 / ZipCrypto)**, **\`.gz\` / \`.tar.gz\` / \`.tgz\`**, **\`.bz2\` / \`.tar.bz2\`**, **\`.xz\` / \`.tar.xz\`**, and **\`.tar\`** archives.

---

## Requirements

### Native Linux Desktop & CLI
- **Operating System**: Any modern Linux distribution (Ubuntu 22.04+, Debian 12+, Linux Mint 21+, Fedora 39+, Arch Linux, Manjaro, Pop!_OS)
- **Python**: Python 3.9 or newer
- **Display Server (GUI)**: Wayland or X11 (GTK4/Libadwaita or Tkinter fallback)
- **Email Client Integration (Optional)**: \`xdg-utils\` (\`xdg-email\`) or \`thunderbird\` for attaching archives directly to an email draft

### Web Workbench (Optional Browser Sandbox)
- **Node.js & npm**: Node.js \`v20.20.2\`, \`npm\` \`10.8.2\`, \`x86_64\` (Rollup-based Vite 6 toolchain)
- **Browser**: Chromium, Firefox, GNOME Web, or Edge with WebAssembly + Web Crypto API (\`window.crypto.subtle\`)

---

## Dependencies

### Linux System & Python Dependencies
| Dependency | Debian / Ubuntu Package | Purpose |
| :--- | :--- | :--- |
| Python Cryptography | \`python3-cryptography\` | \`AESGCM\`, \`PBKDF2HMAC\`, SHA-256 for \`.klock\` |
| GTK4 + Libadwaita | \`python3-gi gir1.2-gtk-4.0 gir1.2-adw-1\` | Native GNOME/Adwaita desktop GUI |
| Tkinter (Fallback) | \`python3-tk\` | Automatic fallback GUI if GTK4 is unavailable |
| 7-Zip | \`p7zip-full\` (or \`7zip\`) | Create & extract \`.7z\` and AES-256 \`.zip\` archives |
| RAR / UnRAR | \`rar unrar\` (or \`unar\`) | Create \`.rar\` and extract/unrar \`.rar\` (with/without passwords) |
| XDG Email / Desktop | \`xdg-utils\` | \`xdg-email --attach\` & desktop/MIME integration |
| Compression Codecs | Built into Python 3 stdlib | \`zipfile\`, \`tarfile\`, \`gzip\`, \`bz2\`, \`lzma\`, \`zlib\` |

Install system dependencies by distro:

- **Ubuntu / Debian / Linux Mint / Pop!_OS**
  \`\`\`bash
  sudo apt update
  sudo apt install -y python3 python3-cryptography python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 p7zip-full unrar rar xdg-utils
  \`\`\`

- **Fedora / RHEL**
  \`\`\`bash
  sudo dnf install -y python3 python3-cryptography python3-gobject gtk4 libadwaita p7zip p7zip-plugins unrar xdg-utils
  \`\`\`

- **Arch Linux / Manjaro**
  \`\`\`bash
  sudo pacman -S --needed python python-cryptography python-gobject gtk4 libadwaita 7zip unrar xdg-utils
  \`\`\`

### Web Workbench Dependencies (in \`package.json\`)
- \`7z-wasm\` — Emscripten WebAssembly 7-Zip (\`.7z\`, \`.tar.gz\`, \`.tar.bz2\`, \`.tar.xz\`, \`.tar\`, \`.xz\`, etc.)
- \`node-unrar-js\` — Official UnRAR WebAssembly (\`.rar\` extraction with and without passwords)
- \`@zip.js/zip.js\` — Pure-JS \`.zip\` creation & extraction (AES-256, ZipCrypto, and unencrypted)
- \`fflate\` — Zlib Deflate, Gzip, and ZIP archive packaging
- \`compressjs\` — Pure-JS Bzip2 codec
- \`lzma\` — Pure-JS LZMA1 codec

---

## Installation

### Option A: Ubuntu / Debian .deb Package (Recommended)
Download \`kryptlock_1.0.0_all.deb\` from the **Linux Native App** tab and run:

    cd ~/Downloads && sudo apt update && sudo apt install -y ./kryptlock_1.0.0_all.deb

Check detected backends and launch:

    kryptlock formats && kryptlock-gui

### Option B: Portable .zip Bundle (All Linux Distros)
Download \`kryptlock-linux-bundle.zip\` and run this single line (do not type \`bash\` by itself on line 1):

    cd ~/Downloads && unzip -o kryptlock-linux-bundle.zip && bash kryptlock-linux/install.sh

---

## How to Use the App

### 1. Native Linux CLI (\`kryptlock\`)
\`\`\`bash
# Create RAR with a password (and encrypted headers) or without a password
kryptlock pack backup.rar ./documents --encrypt-headers --write-checksum
kryptlock pack backup-open.rar ./documents --no-password

# Extract (UnRAR) a password-protected or unencrypted .rar archive
kryptlock unpack backup.rar -o ./restored
kryptlock unpack backup-open.rar -o ./restored --no-password

# Create & extract 7-Zip (.7z) with or without password
kryptlock pack vault.7z ./secrets --encrypt-headers --write-checksum
kryptlock pack public.7z ./assets --no-password
kryptlock unpack vault.7z -o ./restored

# Create & extract ZIP (.zip) with AES-256 password or unencrypted
kryptlock pack release.zip ./dist
kryptlock pack release-open.zip ./dist --no-password

# Gzip, Bzip2, and XZ tarballs
kryptlock pack logs.tar.gz ./var-log
kryptlock pack logs.tar.bz2 ./var-log
kryptlock pack logs.tar.xz ./var-log

# KryptLock (.klock) AES-256-GCM vault with SHA-256 verification & email attachment
kryptlock lock secrets.klock ./documents --algo lzma --write-checksum --email colleague@example.com
kryptlock email vault.7z --to colleague@example.com
\`\`\`

### 2. Native Linux Desktop GUI (\`kryptlock-gui\`)
1. Launch **KryptLock** from your application menu or run \`kryptlock-gui\`.
2. In **Pack & Lock**, add files or folders, choose a format (\`klock\`, \`rar\`, \`7z\`, \`zip\`, \`tar.gz\`, \`tar.bz2\`, \`tar.xz\`, \`gz\`), optionally set a password (or leave blank for unencrypted \`.rar\`/\`.7z\`/\`.zip\`), and click **Create Archive**.
3. Click **Email Archive** to open your Linux mail app (\`xdg-email\` / Thunderbird) with the archive and \`.sha256\` sidecar attached.
4. In **Unpack & Verify**, select any \`.klock\`, \`.rar\`, \`.7z\`, \`.zip\`, \`.gz\`, \`.bz2\`, or \`.xz\` file, enter a password if locked, and extract.

### 3. Browser Workbench
1. In **Pack & Lock**, drop multiple files or folders, pick \`.klock\`, \`.7z\`, \`.zip\`, \`.gz / .tar.gz\`, \`.bz2 / .tar.bz2\`, or \`.xz / .tar.xz\`, and enter an optional password (required for \`.klock\`).
2. In **Unpack & Extract**, drop any \`.klock\`, \`.rar\`, \`.7z\`, \`.zip\`, \`.gz\`, \`.bz2\`, \`.xz\`, or \`.tar\` archive (with or without a password) to verify SHA-256 checksums, preview files, and extract locally.
`;

export const LINUX_BUNDLE_FILES: LinuxBundleFile[] = [
  {
    filename: 'kryptlock.py',
    label: 'CLI & Multi-Format Engine',
    language: 'python',
    executable: true,
    content: KRYPTLOCK_PY,
  },
  {
    filename: 'kryptlock_gui.py',
    label: 'GTK4 + Tkinter GUI',
    language: 'python',
    executable: true,
    content: KRYPTLOCK_GUI_PY,
  },
  {
    filename: 'install.sh',
    label: 'Installer Script',
    language: 'bash',
    executable: true,
    content: INSTALL_SH,
  },
  {
    filename: 'kryptlock.desktop',
    label: 'Desktop Launcher',
    language: 'ini',
    content: KRYPTLOCK_DESKTOP_TEMPLATE,
  },
  {
    filename: 'kryptlock-mime.xml',
    label: 'MIME Association',
    language: 'xml',
    content: KRYPTLOCK_MIME_XML,
  },
  {
    filename: 'kryptlock.svg',
    label: 'Desktop App Icon',
    language: 'xml',
    content: KRYPTLOCK_SVG,
  },
  {
    filename: 'nautilus-script.sh',
    label: 'File Manager Menu',
    language: 'bash',
    executable: true,
    content: NAUTILUS_SCRIPT_SH,
  },
  {
    filename: 'debian-control',
    label: 'Ubuntu .deb Control Metadata',
    language: 'ini',
    content: DEB_CONTROL_TEMPLATE,
  },
  {
    filename: 'README.md',
    label: 'Documentation',
    language: 'markdown',
    content: README_MD,
  },
];

export function downloadLinuxBundleZip(): void {
  const entries: Record<string, Uint8Array> = {};
  for (const file of LINUX_BUNDLE_FILES) {
    if (file.filename === 'debian-control') continue;
    entries[`kryptlock-linux/${file.filename}`] = strToU8(file.content);
  }
  const zipped = zipSync(entries, { level: 9 });
  const copy = new Uint8Array(zipped.byteLength);
  copy.set(zipped);
  const blob = new Blob([copy], { type: 'application/zip' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'kryptlock-linux-bundle.zip';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
