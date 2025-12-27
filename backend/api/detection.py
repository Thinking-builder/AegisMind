import json
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from backend.models.schemas import (
    ApiResponse,
    BatchDetectionResponse,
    BatchFileResult,
    DetectionRequest,
    DetectionResult,
    FileMeta,
    PerformanceMetrics,
    RunDetectionRequest,
)
from backend.services.ai_detector import AIDetector
from backend.services.dynamic_detector import DynamicDetector
from backend.services.evaluation import evaluate, load_ground_truth
from backend.services.llm_service import LLMService
from backend.services.static_detector import StaticDetector
from backend.services.storage import StorageService


router = APIRouter(prefix="/api/detection", tags=["detection"])
storage = StorageService()
static_detector = StaticDetector()
ai_detector = AIDetector()
dynamic_detector = DynamicDetector()
llm_service = LLMService()


def _run_module(module: str, meta: FileMeta) -> DetectionResult:
    path = Path(meta.file_path)
    if module == "static":
        if meta.file_type == "EVTX":
            return DetectionResult(module="static", status="skipped", message="EVTX不适用静态检测")
        return static_detector.scan(path)
    if module == "ai":
        if meta.file_type == "EVTX":
            return DetectionResult(module="ai", status="skipped", message="EVTX不适用AI检测")
        return ai_detector.predict(path)
    if module == "dynamic":
        if meta.file_type != "EVTX":
            return DetectionResult(module="dynamic", status="skipped", message="仅EVTX支持动态检测")
        return dynamic_detector.scan(path)
    return DetectionResult(module=module, status="skipped", message="未知模块")


@router.post("/static", response_model=ApiResponse)
async def static_detect(req: DetectionRequest):
    try:
        meta = storage.get(req.file_id)
        result = _run_module("static", meta)
        return ApiResponse(data=result)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/ai", response_model=ApiResponse)
async def ai_detect(req: DetectionRequest):
    try:
        meta = storage.get(req.file_id)
        result = _run_module("ai", meta)
        return ApiResponse(data=result)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/dynamic", response_model=ApiResponse)
async def dynamic_detect(req: DetectionRequest):
    try:
        meta = storage.get(req.file_id)
        result = _run_module("dynamic", meta)
        return ApiResponse(data=result)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/run", response_model=ApiResponse)
async def run_detection(req: RunDetectionRequest):
    try:
        meta = storage.get(req.file_id)
        requested = req.modules or (["dynamic"] if meta.file_type == "EVTX" else ["static", "ai"])
        results: List[DetectionResult] = []
        for module in requested:
            results.append(_run_module(module, meta))
        report = llm_service.generate_report(meta, results, internet=req.internet)
        return ApiResponse(
            data={
                "file": meta,
                "modules": requested,
                "results": results,
                "llm_report": report,
            }
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/batch", response_model=ApiResponse)
async def batch_detection(
    files: List[UploadFile] = File(...),
    modules: Optional[str] = Form(None),
    ground_truth: Optional[UploadFile] = File(None),
):
    try:
        selected_modules = json.loads(modules) if modules else None
    except json.JSONDecodeError:
        selected_modules = None

    stored, errors = storage.save_batch(files)
    batch_results: List[BatchFileResult] = []
    predictions: Dict[str, bool] = {}

    for meta in stored:
        effective_modules = selected_modules or (["dynamic"] if meta.file_type == "EVTX" else ["static", "ai"])
        result_map: Dict[str, DetectionResult] = {}
        malicious_score = 0.0

        for module in effective_modules:
            result = _run_module(module, meta)
            result_map[module] = result
            if module == "ai" and result.prediction and "malicious_probability" in result.prediction:
                malicious_score = float(result.prediction["malicious_probability"])

        verdict_bool = any(r.is_malicious for r in result_map.values() if r.is_malicious is not None)
        predictions[meta.filename] = verdict_bool
        batch_results.append(
            BatchFileResult(
                file_id=meta.file_id,
                filename=meta.filename,
                file_type=meta.file_type,
                verdict="malicious" if verdict_bool else "benign",
                malicious_score=malicious_score if malicious_score else None,
                results=result_map,
            )
        )

    metrics: Optional[PerformanceMetrics] = None
    if ground_truth:
        gt_bytes = await ground_truth.read()
        gt_map = load_ground_truth(gt_bytes)
        metrics, _ = evaluate(predictions, gt_map)

    response = BatchDetectionResponse(total=len(batch_results), results=batch_results, metrics=metrics)
    payload = ApiResponse(
        data={
            "summary": {"errors": errors},
            "result": response,
        }
    )
    if errors:
        payload.message = "部分文件处理失败"
    return payload
