import json
from pathlib import Path
from typing import Dict, List, Optional

import httpx

from backend.config import settings
from backend.models.schemas import DetectionResult, FileMeta, LLMResponse


class LLMService:
    def __init__(self, config_path: Optional[Path] = None) -> None:
        self.config_path = config_path or settings.LLM_CONFIG_PATH
        self.config: Optional[Dict] = self._load_config()

    def _load_config(self) -> Optional[Dict]:
        if self.config_path.exists():
            try:
                return json.loads(self.config_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
        return None

    def _build_prompt(self, file_meta: FileMeta, results: List[DetectionResult], internet: bool) -> str:
        summary_lines = []
        for res in results:
            summary_lines.append(f"- module: {res.module} | status: {res.status} | malicious: {res.is_malicious}")
            if res.message:
                summary_lines.append(f"  detail: {res.message}")
            if res.matches:
                summary_lines.append(f"  rule_hits: {[m.rule_name for m in res.matches]}")
            if res.prediction:
                summary_lines.append(f"  prediction: {res.prediction}")

        detection_section = "\n".join(summary_lines) if summary_lines else "- no detection results"
        internet_note = (
            "Internet enabled: use static/dynamic detection results as search keywords, such as rule names, sample hash, suspected family, "
            "event IDs, suspicious strings, process/command names, and timestamps. Summarize any findings and cite the key indicators."
            if internet
            else "Internet disabled: analyze only with current detection results and do not add external information."
        )

        prompt = f"""You are a senior malware analyst. Write a Markdown report.
Sample name: {file_meta.filename}
File type: {file_meta.file_type}
File size: {file_meta.file_size} bytes
MD5: {file_meta.md5}

## Detection Results
{detection_section}

## Internet Strategy
{internet_note}

## Report Requirements
1. Sample overview (type, size, hash)
2. Threat level assessment
3. Detection results summary (include rule hits and events)
4. Behavior analysis (combine static/dynamic signals)
5. Threat intelligence correlation (only when internet is enabled)
6. Protection recommendations (endpoint, network, patching)

Please respond in Chinese and use clear Markdown headings/bullets.
"""
        return prompt

    def generate_report(self, file_meta: FileMeta, results: List[DetectionResult], internet: bool = False) -> LLMResponse:
        prompt = self._build_prompt(file_meta, results, internet)
        if not self.config or "api_key" not in self.config or "model" not in self.config:
            fallback = [
                "# LLM not configured",
                "Detection results are ready. Fill llm_config.json to enable GLM.",
                "",
                "## Prompt Preview",
                prompt,
            ]
            return LLMResponse(report="\n".join(fallback), used_internet=False, provider="local-fallback")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config['api_key']}",
        }
        payload = {
            "model": self.config.get("model", "glm-4"),
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a senior security analyst. Output a Markdown report. "
                        "If internet is enabled, search based on detection results and cite key indicators."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        extra_params = self.config.get("extra_params") or {}
        extra_params["enable_internet"] = bool(internet)
        payload.update(extra_params)

        try:
            with httpx.Client(timeout=self.config.get("timeout", 60)) as client:
                resp = client.post(self.config.get("base_url"), headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = ""
                if isinstance(data, dict):
                    choices = data.get("choices")
                    if choices and isinstance(choices, list):
                        content = choices[0].get("message", {}).get("content", "")
                    elif "data" in data:
                        content = data["data"]
                report_text = content or "LLM call succeeded but returned empty content."
                return LLMResponse(report=report_text, used_internet=internet, provider="glm")
        except Exception as exc:  # noqa: BLE001
            fallback = [
                "# LLM call failed, using local prompt preview",
                f"error: {exc}",
                "",
                prompt,
            ]
            return LLMResponse(report="\n".join(fallback), used_internet=False, provider="glm-fallback")
