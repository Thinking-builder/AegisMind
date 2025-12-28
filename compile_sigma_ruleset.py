import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

try:
    from sigma.parser.collection import SigmaCollectionParser
    from sigma.parser.exceptions import SigmaCollectionParseError, SigmaParseError
    HAS_SIGMA = True
except Exception:
    SigmaCollectionParser = None
    SigmaCollectionParseError = SigmaParseError = Exception
    HAS_SIGMA = False


ROOT = Path(__file__).resolve().parent
SIGMA_DIR = ROOT / "Sigma_rules"
OUTPUT_DIR = ROOT / "compiled_rules" / "sigma_ruleset"
FILTERED_DIR = OUTPUT_DIR / "rules_filtered"
RULESET_FILE = OUTPUT_DIR / "ruleset.json"

OUTPUT_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "tags",
    "falsepositives",
    "level",
    "filename",
]


def is_valid_sigma(rule_path: Path) -> bool:
    try:
        content = rule_path.read_text(encoding="utf-8", errors="ignore")
        data = yaml.safe_load(content)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    logsource = data.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        return False
    if isinstance(logsource, dict):
        category = logsource.get("category")
        if category is not None and not isinstance(category, str):
            return False
    detection = data.get("detection")
    if detection is not None and not isinstance(detection, dict):
        return False
    tags = data.get("tags")
    if tags is not None:
        if isinstance(tags, str):
            tags = [tags]
        if not isinstance(tags, (list, tuple, set)):
            return False
        for tag in tags:
            if not isinstance(tag, str):
                return False
            if "." not in tag.strip():
                return False
    if HAS_SIGMA and SigmaCollectionParser is not None:
        try:
            SigmaCollectionParser(content, filename=rule_path)
        except (SigmaCollectionParseError, SigmaParseError, Exception):
            return False
    return True


def prepare_rules() -> dict:
    if FILTERED_DIR.exists():
        shutil.rmtree(FILTERED_DIR, ignore_errors=True)
    FILTERED_DIR.mkdir(parents=True, exist_ok=True)
    skipped = 0
    total = 0
    for pattern in ("*.yml", "*.yaml"):
        for path in SIGMA_DIR.glob(pattern):
            total += 1
            if is_valid_sigma(path):
                shutil.copy2(path, FILTERED_DIR / path.name)
            else:
                skipped += 1
    return {"total": total, "skipped": skipped}


def build_ruleset() -> None:
    cmd = [
        sys.executable,
        "-m",
        "sigma.sigmac",
        "-t",
        "sqlite",
        "--config",
        "zircolite",
        "--backend-option",
        "table=logs",
        "--output-format",
        "json",
        "--output-fields",
        ",".join(OUTPUT_FIELDS),
        "--output",
        str(RULESET_FILE),
        "--defer-abort",
        "--ignore-backend-errors",
        "--recurse",
        str(FILTERED_DIR),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    if RULESET_FILE.exists():
        return
    stderr = (proc.stderr or "").strip()
    message = stderr.splitlines()[-1] if stderr else "sigmac failed to generate ruleset.json"
    raise SystemExit(message)


def main() -> None:
    if not SIGMA_DIR.exists():
        raise SystemExit(f"Sigma rules not found: {SIGMA_DIR}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    counts = prepare_rules()
    if not any(FILTERED_DIR.glob("*.yml")) and not any(FILTERED_DIR.glob("*.yaml")):
        raise SystemExit("No valid Sigma rules after filtering.")

    build_ruleset()

    summary = {
        "rules_filtered_dir": str(FILTERED_DIR),
        "output_dir": str(OUTPUT_DIR),
        "ruleset_file": str(RULESET_FILE),
        "total_rules": counts["total"],
        "skipped_rules": counts["skipped"],
        "sigmac_available": HAS_SIGMA,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
