from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.models.schemas import ApiResponse
from backend.services.storage import StorageService


router = APIRouter(prefix="/api/upload", tags=["upload"])
storage = StorageService()


@router.post("/single", response_model=ApiResponse)
async def upload_single(file: UploadFile = File(...)):
    try:
        meta = storage.save_file(file)
        return ApiResponse(data=meta)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/batch", response_model=ApiResponse)
async def upload_batch(files: list[UploadFile] = File(...)):
    try:
        stored, errors = storage.save_batch(files)
        data = {"total": len(stored), "files": stored, "errors": errors}
        return ApiResponse(data=data, message="partial success" if errors else "success")
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))
