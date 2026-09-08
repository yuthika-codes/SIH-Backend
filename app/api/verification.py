from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/verification", tags=["verification"])


class VerificationRequest(BaseModel):
    expected_sha256: str
    actual_sha256: str


@router.post("/hash")
def verify_hash(payload: VerificationRequest) -> dict[str, bool]:
    return {"valid": payload.expected_sha256.lower() == payload.actual_sha256.lower()}
