from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.services.database import get_db

router = APIRouter(prefix="/cases", tags=["cases"])


class CaseCreate(BaseModel):
    title: str
    description: str | None = None
    created_by: str | None = None


class CaseResponse(CaseCreate):
    id: str
    status: str


@router.post("", response_model=CaseResponse, status_code=201)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)) -> Case:
    case = Case(id=str(uuid4()), **payload.model_dump())
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


@router.get("", response_model=list[CaseResponse])
def list_cases(db: Session = Depends(get_db)) -> list[Case]:
    return list(db.scalars(select(Case).order_by(Case.created_at.desc())))


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, db: Session = Depends(get_db)) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case
