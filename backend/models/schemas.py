from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ApiResponse(BaseModel):
    code: int = 200
    message: str = "success"
    data: Optional[Any] = None


class FileMeta(BaseModel):
    file_id: str
    filename: str
    file_type: str
    file_size: int
    md5: str
    upload_time: datetime
    file_path: str


class StaticMatch(BaseModel):
    rule_name: str
    namespace: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    module: str
    status: str
    is_malicious: Optional[bool] = None
    message: Optional[str] = None
    execution_time_ms: Optional[float] = None
    matches: Optional[List[StaticMatch]] = None
    prediction: Optional[Dict[str, Any]] = None
    summary: Optional[str] = None


class DetectionRequest(BaseModel):
    file_id: str


class RunDetectionRequest(BaseModel):
    file_id: str
    modules: List[str] = Field(default_factory=list)
    internet: bool = False


class LLMRequest(BaseModel):
    file_id: str
    modules: List[str] = Field(default_factory=list)
    detection_results: List[DetectionResult]
    internet: bool = False


class LLMResponse(BaseModel):
    report: str
    used_internet: bool = False
    provider: str = "glm"


class BatchFileResult(BaseModel):
    file_id: str
    filename: str
    file_type: str
    verdict: str
    results: Dict[str, DetectionResult] = Field(default_factory=dict)
    malicious_score: Optional[float] = None


class PerformanceMetrics(BaseModel):
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    false_negative_rate: Optional[float] = None
    false_positive_rate: Optional[float] = None
    false_negatives: List[str] = Field(default_factory=list)
    false_positives: List[str] = Field(default_factory=list)


class BatchDetectionResponse(BaseModel):
    total: int
    results: List[BatchFileResult]
    metrics: Optional[PerformanceMetrics] = None
