from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.user import User
from app.services.database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class UserCreate(BaseModel):
    username: str
    role: str = "investigator"


@router.post("/users", response_model=dict[str, str], status_code=201)
def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> dict[str, str]:
    user = User(id=str(uuid4()), username=payload.username, role=payload.role)
    db.add(user)
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}
