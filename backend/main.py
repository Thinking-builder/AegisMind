from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import detection, health, llm, upload
from backend.models.schemas import ApiResponse

app = FastAPI(
    title="恶意文件检测平台 API",
    description="基于YARA + Sigma + MalConv + LLM的检测接口",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_model=ApiResponse)
async def root():
    return ApiResponse(data={"service": "malware-detection", "status": "ok"})


app.include_router(health.router)
app.include_router(upload.router)
app.include_router(detection.router)
app.include_router(llm.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
