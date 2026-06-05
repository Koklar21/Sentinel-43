from fastapi import APIRouter

router = APIRouter(
    prefix="/audit",
    tags=["audit"]
)

@router.get("/health")
async def audit_health():
    return {"status": "ok"}
