import json
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile

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
from backend.services.batch_tasks import batch_store
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
        return dynamic_detector.scan(path, file_id=meta.file_id)
    return DetectionResult(module=module, status="skipped", message="未知模块")


def _build_batch_result(meta: FileMeta, effective_modules: List[str]) -> tuple[BatchFileResult, bool]:
    result_map: Dict[str, DetectionResult] = {}
    malicious_score = 0.0
    for module in effective_modules:
        result = _run_module(module, meta)
        result_map[module] = result
        if module == "ai" and result.prediction and "malicious_probability" in result.prediction:
            malicious_score = float(result.prediction["malicious_probability"])
    verdict_bool = any(r.is_malicious for r in result_map.values() if r.is_malicious is not None)
    batch_result = BatchFileResult(
        file_id=meta.file_id,
        filename=meta.filename,
        file_type=meta.file_type,
        verdict="malicious" if verdict_bool else "benign",
        malicious_score=malicious_score if malicious_score else None,
        results=result_map,
    )
    return batch_result, verdict_bool


def _run_batch_task(
    task_id: str,
    stored: List[FileMeta],
    selected_modules: Optional[List[str]],
    gt_bytes: Optional[bytes],
) -> None:
    try:
        predictions: Dict[str, bool] = {}
        gt_map = load_ground_truth(gt_bytes) if gt_bytes else {}
        for meta in stored:
            batch_store.set_current(task_id, meta.filename)
            try:
                effective_modules = selected_modules or (["dynamic"] if meta.file_type == "EVTX" else ["static", "ai"])
                batch_result, verdict_bool = _build_batch_result(meta, effective_modules)
                predictions[meta.filename] = verdict_bool
                batch_store.add_result(task_id, batch_result)
            except Exception as exc:  # noqa: BLE001
                batch_store.add_error(task_id, f"{meta.filename}: {exc}")
            finally:
                batch_store.advance(task_id)

        metrics = None
        if gt_map:
            metrics, _ = evaluate(predictions, gt_map)
        batch_store.complete(task_id, metrics)
    except Exception as exc:  # noqa: BLE001
        batch_store.fail(task_id, str(exc))


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


@router.post("/batch/start", response_model=ApiResponse)
async def batch_start(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    modules: Optional[str] = Form(None),
    ground_truth: Optional[UploadFile] = File(None),
):
    try:
        selected_modules = json.loads(modules) if modules else None
    except json.JSONDecodeError:
        selected_modules = None

    stored, errors = storage.save_batch(files)
    task = batch_store.create(total=len(stored), errors=errors)
    gt_bytes = await ground_truth.read() if ground_truth else None
    background_tasks.add_task(_run_batch_task, task.task_id, stored, selected_modules, gt_bytes)
    return ApiResponse(data={"task_id": task.task_id, "total": task.total, "errors": errors})


@router.get("/batch/status/{task_id}", response_model=ApiResponse)
async def batch_status(task_id: str):
    try:
        task = batch_store.get(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"batch task not found: {exc}")

    percent = round((task.completed / task.total) * 100, 2) if task.total else 0.0
    payload = {
        "task_id": task.task_id,
        "status": task.status,
        "total": task.total,
        "completed": task.completed,
        "current": task.current,
        "percent": percent,
        "errors": task.errors,
        "message": task.message,
    }
    if task.status == "completed":
        payload["result"] = BatchDetectionResponse(
            total=task.total,
            results=task.results,
            metrics=task.metrics,
        )
    return ApiResponse(data=payload)


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
        batch_result, verdict_bool = _build_batch_result(meta, effective_modules)
        predictions[meta.filename] = verdict_bool
        batch_results.append(batch_result)

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
