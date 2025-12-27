import csv
import io
import json
from typing import Dict, Optional, Tuple

from backend.models.schemas import PerformanceMetrics


def _parse_label(value: str) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "malicious", "malware", "yes", "y"}:
        return 1
    if text in {"0", "false", "benign", "clean", "no", "n"}:
        return 0
    try:
        num = int(float(text))
        return 1 if num > 0 else 0
    except ValueError:
        return None


def _find_name_key(row: Dict[str, str]) -> Optional[str]:
    for key in row:
        key_lower = key.lower()
        if key_lower in {"name", "filename", "file", "sample"}:
            return key
        if "file" in key_lower or "filename" in key_lower:
            return key
    return None


def _find_label_key(row: Dict[str, str]) -> Optional[str]:
    for key in row:
        key_lower = key.lower()
        if key_lower in {"label", "gt", "truth", "is_mal", "ismal", "is_malicious"}:
            return key
        if "label" in key_lower or "恶意" in key or "mal" in key_lower:
            return key
    return None


def load_ground_truth(file_content: bytes) -> Dict[str, int]:
    if not file_content:
        return {}
    # Try JSON first
    try:
        data = json.loads(file_content.decode("utf-8"))
        if isinstance(data, dict):
            return {k: int(v) for k, v in data.items() if str(v).isdigit()}
        if isinstance(data, list):
            result = {}
            for item in data:
                if isinstance(item, dict):
                    name_key = _find_name_key(item)
                    label_key = _find_label_key(item)
                    if name_key and label_key:
                        parsed = _parse_label(item[label_key])
                        if parsed is not None:
                            result[item[name_key]] = parsed
            return result
    except Exception:
        pass

    try:
        text_stream = io.StringIO(file_content.decode("utf-8"))
        reader = csv.DictReader(text_stream)
        result = {}
        for row in reader:
            name_key = _find_name_key(row)
            label_key = _find_label_key(row)
            if name_key and label_key:
                parsed = _parse_label(row[label_key])
                if parsed is not None:
                    result[row[name_key]] = parsed
        return result
    except Exception:
        return {}


def evaluate(predictions: Dict[str, bool], ground_truth: Dict[str, int]) -> Tuple[PerformanceMetrics, Dict[str, bool]]:
    tp = tn = fp = fn = 0
    verdicts: Dict[str, bool] = {}
    for name, pred in predictions.items():
        if name not in ground_truth:
            continue
        actual = bool(int(ground_truth[name]))
        verdicts[name] = pred
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif (not pred) and actual:
            fn += 1
        else:
            tn += 1
    total = tp + tn + fp + fn
    if total == 0:
        return PerformanceMetrics(), verdicts
    pos_total = tp + fn
    neg_total = tn + fp
    metrics = PerformanceMetrics(
        accuracy=round((tp + tn) / total, 4),
        precision=round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        recall=round(tp / pos_total, 4) if pos_total else 0.0,
        # 依据约定：漏报率 = 标签为恶意且判断为良性的数量 / 总样本数
        false_negative_rate=round(fn / total, 4) if total else 0.0,
        # 错报率 = 标签为良性样本中被判断为恶意的数量 / 良性样本数量
        false_positive_rate=round(fp / neg_total, 4) if neg_total else 0.0,
        false_negatives=[
            name
            for name, pred in predictions.items()
            if name in ground_truth and ground_truth[name] and not pred
        ],
        false_positives=[
            name
            for name, pred in predictions.items()
            if name in ground_truth and not ground_truth[name] and pred
        ],
    )
    return metrics, verdicts
