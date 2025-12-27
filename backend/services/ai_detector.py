import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

from backend.config import settings
from backend.models.schemas import DetectionResult


class AIDetector:
    def __init__(self) -> None:
        self._model = None
        self._device = None
        self._load_error: Optional[str] = None

    def _load_model(self) -> None:
        if self._model is not None or self._load_error:
            return
        try:
            import torch
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"缺少PyTorch依赖: {exc}"
            return

        sys.path.append(str(settings.MALCONV_DIR))
        try:
            from MalConvGCT_nocat import MalConvGCT  # type: ignore
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"加载MalConv模型定义失败: {exc}"
            return

        checkpoint_path = settings.MALCONV_DIR / "malconvGCT_nocat.checkpoint"
        if not checkpoint_path.exists():
            self._load_error = f"未找到模型权重: {checkpoint_path}"
            return
        try:
            self._device = "cpu"
            model = MalConvGCT(channels=256, window_size=256, stride=64, low_mem=False)
            ckpt = torch.load(checkpoint_path, map_location=torch.device(self._device))
            if isinstance(ckpt, dict) and "model_state_dict" in ckpt:
                model.load_state_dict(ckpt["model_state_dict"], strict=False)
            else:
                model.load_state_dict(ckpt, strict=False)
            model.eval()
            self._model = model
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"加载模型失败: {exc}"

    def _prepare_tensor(self, file_path: Path, max_len: int = 4_000_000):
        try:
            with open(file_path, "rb") as f:
                raw = f.read(max_len)
                arr = np.frombuffer(raw, dtype=np.uint8).astype(np.int16) + 1
            import torch

            tensor = torch.tensor(arr).unsqueeze(0)
            return tensor, len(raw)
        except Exception:
            return None, 0

    def predict(self, file_path: Path) -> DetectionResult:
        start = time.perf_counter()
        self._load_model()
        if self._load_error:
            return DetectionResult(module="ai", status="failed", message=self._load_error)
        if self._model is None:
            return DetectionResult(module="ai", status="failed", message="AI模型未就绪")
        tensor, consumed = self._prepare_tensor(file_path)
        if tensor is None:
            return DetectionResult(module="ai", status="failed", message="读取文件失败")
        try:
            import torch

            with torch.no_grad():
                logits, *_ = self._model(tensor)
                prob = torch.nn.functional.softmax(logits, dim=1)[0][1].item()
                verdict = prob > 0.5
            return DetectionResult(
                module="ai",
                status="success",
                is_malicious=verdict,
                prediction={
                    "malicious_probability": round(prob, 4),
                    "bytes_evaluated": consumed,
                },
                execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
                message="AI检测完成",
            )
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(
                module="ai",
                status="failed",
                is_malicious=None,
                message=f"AI检测失败: {exc}",
            )
