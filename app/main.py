from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import analysis, auth, cases, custody, evidence, reports, verification
from app.services.database import init_db
from app.services.storage import ensure_storage


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    ensure_storage()
    yield

app = FastAPI(
    title="SIH Forensic Evidence API",
    version="0.1.0",
    description="Case, evidence, chain-of-custody, and forensic analysis services.",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(analysis.router)
app.include_router(verification.router)
app.include_router(custody.router)
app.include_router(reports.router)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}
