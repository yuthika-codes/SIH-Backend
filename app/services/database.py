import os
from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sih.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.models import analysis  # noqa: F401
    from app.models import audit, case, custody, evidence, user  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _migrate_existing_schema()


def _migrate_existing_schema() -> None:
    """Add nullable integrity fields to an existing SQLite database."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    additions = {
        "evidence": {
            "original_path": "TEXT",
            "original_sha256": "VARCHAR(64)",
            "md5": "VARCHAR(32)",
            "size_bytes": "INTEGER",
            "acquired_path": "TEXT",
            "acquired_sha256": "VARCHAR(64)",
            "integrity_verified": "BOOLEAN",
            "integrity_status": "VARCHAR(30)",
            "acquired_at": "DATETIME",
        },
        "custody_events": {
            "description": "TEXT",
            "sha256": "VARCHAR(64)",
            "metadata_json": "TEXT",
        },
    }
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table, columns in additions.items():
            existing = {column["name"] for column in inspector.get_columns(table)}
            for column, definition in columns.items():
                if column not in existing:
                    connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}'))
