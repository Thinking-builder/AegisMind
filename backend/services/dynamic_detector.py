import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml
from Evtx.Evtx import Evtx  # type: ignore

from backend.config import settings
from backend.models.schemas import DetectionResult


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    level: Optional[str]
    event_ids: Set[int]
    keywords: List[str]


class DynamicDetector:
    def __init__(self, rules_dir: Optional[Path] = None, max_rules: int = 400) -> None:
        self.rules_dir = rules_dir or settings.SIGMA_RULE_DIR
        self.max_rules = max_rules
        self._rules: List[SigmaRule] = []
        self._load_error: Optional[str] = None
        self._loaded = False

    def _extract_keywords(self, node) -> List[str]:  # noqa: ANN001
        keywords: List[str] = []
        if isinstance(node, str):
            keywords.append(node)
        elif isinstance(node, list):
            for item in node:
                keywords.extend(self._extract_keywords(item))
        elif isinstance(node, dict):
            for value in node.values():
                keywords.extend(self._extract_keywords(value))
        return keywords

    def _load_rules(self) -> None:
        self._loaded = True
        if not self.rules_dir.exists():
            self._load_error = f"Sigma规则目录不存在: {self.rules_dir}"
            return
        count = 0
        for path in sorted(self.rules_dir.glob("*.yml")):
            if count >= self.max_rules:
                break
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            logsource = (data or {}).get("logsource", {})
            product = (logsource or {}).get("product", "") or ""
            service = (logsource or {}).get("service", "") or ""
            if "windows" not in product.lower() and not path.name.startswith("win_") and "windows" not in service.lower():
                continue
            detection = (data or {}).get("detection", {}) or {}
            event_ids: Set[int] = set()
            for val in detection.values():
                if isinstance(val, dict):
                    for k, v in val.items():
                        if k.lower() == "eventid":
                            if isinstance(v, list):
                                event_ids.update({int(x) for x in v if str(x).isdigit()})
                            elif str(v).isdigit():
                                event_ids.add(int(v))
            keywords = self._extract_keywords(detection)
            self._rules.append(
                SigmaRule(
                    rule_id=data.get("id", path.stem),
                    title=data.get("title", path.stem),
                    level=data.get("level"),
                    event_ids=event_ids,
                    keywords=[kw for kw in keywords if isinstance(kw, str)],
                )
            )
            count += 1
        if not self._rules:
            self._load_error = "未成功加载Sigma规则"

    def _read_events(self, evtx_path: Path) -> List[Dict]:
        events: List[Dict] = []
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                try:
                    event_id = int(root.findtext("./System/EventID") or -1)
                except ValueError:
                    event_id = -1
                data_nodes = root.findall(".//Data")
                text_parts = [d.text for d in data_nodes if d.text]
                events.append({"event_id": event_id, "text": " ".join(text_parts)})
        return events

    def scan(self, evtx_path: Path) -> DetectionResult:
        start = time.perf_counter()
        if not self._loaded:
            self._load_rules()
        if self._load_error:
            return DetectionResult(module="dynamic", status="failed", message=self._load_error)
        try:
            events = self._read_events(evtx_path)
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(
                module="dynamic",
                status="failed",
                message=f"解析EVTX失败: {exc}",
            )

        matched: List[Dict[str, str]] = []
        for rule in self._rules:
            for event in events:
                if rule.event_ids and event["event_id"] not in rule.event_ids:
                    continue
                if rule.keywords:
                    text_lower = event["text"].lower()
                    if not any(str(kw).lower() in text_lower for kw in rule.keywords):
                        continue
                matched.append(
                    {
                        "rule_id": rule.rule_id,
                        "title": rule.title,
                        "event_id": event["event_id"],
                        "level": rule.level,
                    }
                )
                break
        return DetectionResult(
            module="dynamic",
            status="success",
            is_malicious=len(matched) > 0,
            prediction={"matches": matched, "events_scanned": len(events)},
            execution_time_ms=round((time.perf_counter() - start) * 1000, 2),
            message=f"命中 {len(matched)} 条Sigma规则" if matched else "未命中Sigma规则",
        )
