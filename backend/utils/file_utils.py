import hashlib
import os
from pathlib import Path
from typing import Tuple

from backend.config import settings


SCRIPT_EXTS = {"ps1", "bat", "cmd", "sh", "py", "js", "vbs"}


def compute_md5(file_path: Path, chunk_size: int = 8192) -> str:
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def detect_file_type(file_path: Path, filename: str) -> str:
    ext = file_path.suffix.lower().replace(".", "") or Path(filename).suffix.lower().replace(".", "")
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
    except FileNotFoundError:
        return "UNKNOWN"

    if header.startswith(b"MZ"):
        return "PE"
    if header.startswith(b"ElfFile") or ext == "evtx":
        return "EVTX"
    if ext in SCRIPT_EXTS:
        return "SCRIPT"
    if ext:
        return ext.upper()
    return "UNKNOWN"


def ensure_within_limit(file_size: int) -> Tuple[bool, str]:
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        return False, f"文件大小超过限制({settings.MAX_FILE_SIZE_MB}MB)"
    return True, ""


def ensure_directories() -> None:
    for path in [settings.UPLOAD_DIR, settings.REPORT_DIR]:
        os.makedirs(path, exist_ok=True)
