import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from uuid import uuid4

from fastapi import UploadFile

from backend.config import settings
from backend.models.schemas import FileMeta
from backend.utils.file_utils import compute_md5, detect_file_type, ensure_directories, ensure_within_limit


class StorageService:
    def __init__(self) -> None:
        ensure_directories()
        self.registry_path = settings.UPLOAD_REGISTRY
        self._registry: Dict[str, Dict] = self._load_registry()

    def _load_registry(self) -> Dict[str, Dict]:
        if self.registry_path.exists():
            try:
                return json.loads(self.registry_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return {}
        return {}

    def _persist_registry(self) -> None:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        # datetime 需要序列化为字符串
        self.registry_path.write_text(
            json.dumps(self._registry, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    def save_file(self, upload: UploadFile) -> FileMeta:
        file_id = str(uuid4())
        dest_dir = settings.UPLOAD_DIR / file_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / upload.filename

        size = 0
        upload.file.seek(0)
        with open(dest_path, "wb") as out_f:
            while True:
                chunk = upload.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                allowed, reason = ensure_within_limit(size)
                if not allowed:
                    upload.file.close()
                    out_f.close()
                    dest_path.unlink(missing_ok=True)
                    raise ValueError(reason)
                out_f.write(chunk)
        upload.file.close()

        file_type = detect_file_type(dest_path, upload.filename)
        md5_value = compute_md5(dest_path)
        meta = FileMeta(
            file_id=file_id,
            filename=upload.filename,
            file_type=file_type,
            file_size=size,
            md5=md5_value,
            upload_time=datetime.utcnow(),
            file_path=str(dest_path),
        )
        # 以 JSON 友好格式存储，datetime 将转为 ISO 字符串
        self._registry[file_id] = meta.model_dump(mode="json")
        self._persist_registry()
        return meta

    def save_batch(self, uploads: List[UploadFile]) -> Tuple[List[FileMeta], List[str]]:
        stored: List[FileMeta] = []
        errors: List[str] = []
        for upload in uploads:
            try:
                stored.append(self.save_file(upload))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{upload.filename}: {exc}")
        return stored, errors

    def get(self, file_id: str) -> FileMeta:
        record = self._registry.get(file_id)
        if not record:
            # 尝试重新加载，以防进程重启或缓存未刷新
            self._registry = self._load_registry()
            record = self._registry.get(file_id)
        if not record:
            raise FileNotFoundError(f"未找到文件ID: {file_id}")
        return FileMeta(**record)

    def exists(self, file_id: str) -> bool:
        return file_id in self._registry

    def cleanup_file(self, file_id: str) -> None:
        if file_id in self._registry:
            path = Path(self._registry[file_id]["file_path"])
            if path.exists():
                shutil.rmtree(path.parent, ignore_errors=True)
            del self._registry[file_id]
            self._persist_registry()
