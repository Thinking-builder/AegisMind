from fastapi import APIRouter

from backend.models.schemas import ApiResponse


router = APIRouter(tags=["health"])


@router.get("/health", response_model=ApiResponse)
async def health_check():
    return ApiResponse(data={"status": "ok"})
