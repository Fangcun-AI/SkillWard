"""
FangcunGuard-SkillsScanner — Standalone skill audit service

Three-layer safety analysis for AI Agent skill operations:
  Layer 0: Rule-based pre-check (deterministic pattern matching)
  Layer 1: Qwen3Guard-Gen-8B (classification model)
  Layer 2: Qwen3-8B (semantic LLM analysis)
"""
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from models.requests import SkillAuditRequest
from models.responses import SkillAuditResponse
from services.skill_audit_service import audit_skill_operation
from utils.logger import setup_logger

logger = setup_logger()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Three-layer skill audit service for AI Agent security",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Optional API key authentication
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if settings.api_secret_key and request.url.path not in ("/", "/health"):
        api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
        if api_key != settings.api_secret_key:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=401, content={"detail": "Invalid API key"})
    return await call_next(request)


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "endpoints": {
            "skill_audit": "POST /v1/skill-audit",
            "health": "GET /health",
        }
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/v1/skill-audit", response_model=SkillAuditResponse)
async def skill_audit(request_data: SkillAuditRequest):
    """
    Skill operation audit API — Three-layer safety analysis.

    Layer 0: Rule engine (credential exfil, env harvesting, sensitive write)
    Layer 1: Qwen3Guard-Gen-8B classification
    Layer 2: Qwen3-8B semantic analysis with rule alerts injected
    """
    try:
        logger.info(
            f"Skill audit request: skill={request_data.skill_name}, "
            f"ops={len(request_data.operations)}, "
            f"current_op={request_data.current_operation[:100]}"
        )
        result = await audit_skill_operation(request_data)
        logger.info(f"Skill audit result: {result.id}, risk={result.risk_level}, action={result.suggest_action}")
        return result
    except Exception as e:
        logger.error(f"Skill audit error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.on_event("shutdown")
async def shutdown():
    from services.model_service import model_service
    from services.general_llm_service import general_llm_service
    await model_service.close()
    await general_llm_service.close()


if __name__ == "__main__":
    print(f"Starting {settings.app_name} v{settings.app_version}")
    print(f"  Classification model: {settings.guardrails_model_name} @ {settings.guardrails_model_api_url}")
    print(f"  Semantic model: {settings.general_llm_model_name} @ {settings.general_llm_api_url}")
    print(f"  Port: {settings.port}")
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
    )
