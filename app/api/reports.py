from fastapi import APIRouter

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{case_id}")
def get_report(case_id: str) -> dict[str, str]:
    return {"case_id": case_id, "status": "report generation pending", "format": "json"}
