import subprocess
import time
from pathlib import Path
from typing import List, Optional, Set

from backend.config import settings
from backend.models.schemas import DetectionResult, StaticMatch


class StaticDetector:
    def __init__(self) -> None:
        self.yara_exe = settings.PROJECT_ROOT / "yara.exe"
        self.compiled_rule = self._resolve_compiled_rule()
        self._load_error: Optional[str] = None

    def _resolve_compiled_rule(self) -> Optional[Path]:
        if settings.COMPILED_YARA_FILE.exists():
            return settings.COMPILED_YARA_FILE
        if settings.COMPILED_YARA_FILE_ALT.exists():
            return settings.COMPILED_YARA_FILE_ALT
        return None

    def _run_yara(self, target: Path) -> List[str]:
        if not self.compiled_rule:
            raise FileNotFoundError("未找到已编译的 YARA 规则文件")
        cmd = [str(self.yara_exe), "-C", str(self.compiled_rule), str(target)]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=60)
        lines = []
        for line in (proc.stdout or "").splitlines():
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
        return lines

    def scan(self, file_path: Path) -> DetectionResult:
        start = time.perf_counter()
        if not self.yara_exe.exists():
            return DetectionResult(module="static", status="failed", message=f"未找到 yara.exe: {self.yara_exe}")
        if not self.compiled_rule:
            return DetectionResult(
                module="static",
                status="failed",
                message="未找到已编译的 all_rules.yac/all_rules.yarc",
            )
        try:
            outputs = self._run_yara(file_path)
        except subprocess.TimeoutExpired:
            return DetectionResult(module="static", status="failed", message="YARA 执行超时")
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(module="static", status="failed", message=f"YARA 执行失败: {exc}")

        matched_names: Set[str] = set()
        for line in outputs:
            rule_name = line.split()[0]
            matched_names.add(rule_name)

        matches = [StaticMatch(rule_name=name) for name in sorted(matched_names)]
        message = f"命中 {len(matches)} 条规则" if matches else "未命中规则"

        return DetectionResult(
            module="static",
            status="success",
            is_malicious=len(matches) > 0,
            matches=matches,
            execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
            message=message,
        )
