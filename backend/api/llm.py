from fastapi import APIRouter, HTTPException

from backend.models.schemas import ApiResponse, LLMRequest
from backend.services.llm_service import LLMService
from backend.services.storage import StorageService


router = APIRouter(prefix="/api/llm", tags=["llm"])
storage = StorageService()
llm_service = LLMService()


@router.post("/generate-report", response_model=ApiResponse)
async def generate_report(req: LLMRequest):
    try:
        meta = storage.get(req.file_id)
        report = llm_service.generate_report(meta, req.detection_results, internet=req.internet)
        return ApiResponse(data=report)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))
