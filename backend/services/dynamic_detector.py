import json
import os
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Set

from backend.config import settings
from backend.models.schemas import DetectionResult, StaticMatch


class DynamicDetector:
    def __init__(self) -> None:
        self.zircolite_dir = settings.PROJECT_ROOT / "zircolite_win"
        self.zircolite_exe = self.zircolite_dir / "zircolite_win_x64_2.40.0.exe"
        self.ruleset = self._resolve_ruleset()
        self.config_path = self.zircolite_dir / "config" / "fieldMappings.json"
        self.evtx_dump = self.zircolite_dir / "bin" / "evtx_dump_win.exe"
        self.output_dir = settings.REPORT_DIR / "zircolite"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_ruleset(self) -> Optional[Path]:
        if settings.ZIRCOLITE_RULESET_ALT.exists():
            return settings.ZIRCOLITE_RULESET_ALT
        if settings.ZIRCOLITE_RULESET.exists():
            return settings.ZIRCOLITE_RULESET
        return None

    def _parse_output(self, output_path: Path) -> List[dict]:
        if not output_path.exists():
            return []
        content = output_path.read_text(encoding="utf-8", errors="ignore").strip()
        if not content:
            return []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            events: List[dict] = []
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return events
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("detections", "events", "results", "alerts", "matches", "data"):
                if key in data and isinstance(data[key], list):
                    return data[key]
        return []

    def _extract_rule_name(self, event: dict) -> Optional[str]:
        for key in ("title", "rule_title", "rule", "rule_name", "name", "id"):
            val = event.get(key)
            if isinstance(val, (str, int)) and str(val).strip():
                return str(val)
        for key in ("sigma", "rule"):
            sub = event.get(key)
            if isinstance(sub, dict):
                for subkey in ("title", "name", "id", "rule", "rule_name"):
                    val = sub.get(subkey)
                    if isinstance(val, (str, int)) and str(val).strip():
                        return str(val)
        return None

    def scan(self, evtx_path: Path, file_id: Optional[str] = None) -> DetectionResult:
        start = time.perf_counter()
        if not self.zircolite_exe.exists():
            return DetectionResult(module="dynamic", status="failed", message=f"未找到 Zircolite: {self.zircolite_exe}")
        if not self.ruleset:
            return DetectionResult(module="dynamic", status="failed", message="未找到预生成 ruleset.json")

        safe_id = file_id or evtx_path.stem
        output_name = f"zircolite_{safe_id}_{int(time.time())}.json"
        output_path = self.output_dir / output_name

        cmd = [
            str(self.zircolite_exe),
            "--evtx",
            str(evtx_path),
            "--ruleset",
            str(self.ruleset),
            "--outfile",
            str(output_path),
        ]
        if self.config_path.exists():
            cmd += ["--config", str(self.config_path)]
        if self.evtx_dump.exists():
            cmd += ["--evtx_dump", str(self.evtx_dump)]
        env = os.environ.copy()
        env["PATH"] = f"{self.zircolite_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                cwd=str(self.zircolite_dir),
                env=env,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return DetectionResult(module="dynamic", status="failed", message="Zircolite 执行超时")
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(module="dynamic", status="failed", message=f"Zircolite 调用失败: {exc}")

        if not output_path.exists():
            stderr = (proc.stderr or "").strip()
            message = stderr or "Zircolite 未生成输出文件"
            return DetectionResult(module="dynamic", status="failed", message=message)

        events = self._parse_output(output_path)
        matched_names: Set[str] = set()
        for event in events:
            if isinstance(event, dict):
                rule_name = self._extract_rule_name(event)
                if rule_name:
                    matched_names.add(rule_name)

        matches = [StaticMatch(rule_name=name) for name in sorted(matched_names)]
        message = f"命中 {len(matches)} 条 Sigma 规则" if matches else "未命中 Sigma 规则"

        return DetectionResult(
            module="dynamic",
            status="success",
            is_malicious=len(matches) > 0,
            matches=matches,
            execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
            message=message,
        )
