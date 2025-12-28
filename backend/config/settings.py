from pathlib import Path
from typing import List


PROJECT_ROOT = Path(__file__).resolve().parent.parent
STORAGE_ROOT = PROJECT_ROOT.parent / "storage"

UPLOAD_DIR = STORAGE_ROOT / "uploads"
REPORT_DIR = STORAGE_ROOT / "reports"
UPLOAD_REGISTRY = UPLOAD_DIR / "metadata.json"

SIGMA_RULE_DIR = PROJECT_ROOT.parent / "Sigma_rules"
YARA_RULE_DIR = PROJECT_ROOT.parent / "yara_rules"
MALCONV_DIR = PROJECT_ROOT.parent / "MalConv2-main"
COMPILED_YARA_DIR = PROJECT_ROOT.parent / "compiled_rules"
COMPILED_YARA_FILE = COMPILED_YARA_DIR / "all_rules.yac"
COMPILED_YARA_FILE_ALT = COMPILED_YARA_DIR / "all_rules.yarc"
ZIRCOLITE_RULESET = PROJECT_ROOT / "zircolite_win" / "rules" / "rules_windows_generic_pysigma.json"
ZIRCOLITE_RULESET_ALT = PROJECT_ROOT.parent / "compiled_rules" / "sigma_ruleset" / "ruleset.json"

LLM_CONFIG_PATH = PROJECT_ROOT / "config" / "llm_config.json"
LLM_CONFIG_EXAMPLE = PROJECT_ROOT / "config" / "llm_config.example.json"

MAX_FILE_SIZE_MB = 100
ALLOWED_EXTENSIONS: List[str] = [
    "exe",
    "dll",
    "sys",
    "bin",
    "evtx",
    "ps1",
    "bat",
    "cmd",
    "sh",
    "py",
    "js",
]
