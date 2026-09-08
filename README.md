# SIH Backend

FastAPI backend for vendor-agnostic DVR/NVR forensic evidence analysis.

## Forensic pipeline

`Evidence -> SHA-256/MD5 hashing -> device identification -> filesystem analysis -> video extraction -> metadata extraction -> timeline -> analysis result`

The pipeline never writes to the original evidence. File acquisitions are copied into `storage/forensic_images/`, and validated extracted media is written to `storage/extracted/`. SHA-256 is the primary integrity hash; MD5 is retained for compatibility and reporting.

## Architecture

- `app/api/` contains the HTTP layer and preserves the existing endpoint names.
- `app/forensic_engine/engine.py` coordinates the pipeline.
- `app/forensic_engine/parsers/` exposes a common parser interface.
- `app/services/` owns database sessions and storage paths.
- SQLite stores references, hashes, metadata, and analysis JSON, never large binary evidence.

## API flow

Upload evidence with `POST /evidence/upload/{case_id}`, then run the pipeline with `POST /analysis/run` using the returned evidence ID:

```json
{"evidence_id": "<uploaded-evidence-id>", "analysis_type": "forensic"}
```

For local processing without a database evidence record, `evidence_path` may be supplied instead.

## Evidence integrity and chain of custody

Evidence upload creates a unique evidence ID, streams the uploaded bytes into the evidence store, and records the original reference, UTC acquisition timestamp, size, SHA-256, and MD5. The backend automatically records `EVIDENCE_UPLOADED` and `HASH_CALCULATED` custody events.

When analysis runs for a stored evidence ID, the backend records acquisition and analysis events, copies the evidence into `storage/forensic_images/`, verifies the acquired SHA-256 against the original, and stores the acquired path/hash and integrity status. A mismatch is recorded as `INTEGRITY_COMPROMISED` and stops further forensic extraction.

Re-verify an acquired item with `GET /verification/{evidence_id}`. The endpoint hashes the acquired file currently on disk and returns `VERIFIED` or `INTEGRITY_COMPROMISED`. Missing evidence or missing acquired copies return clear HTTP errors. Chain-of-custody records are created by the backend; clients do not need to submit them.

## Supported formats and limitations

Common video extensions (`.mp4`, `.avi`, `.mkv`, `.mov`, `.h264`, `.h265`, `.ts`, `.m2ts`, `.webm`) are passed through FFmpeg when it is installed and the file validates. `.dav` and other proprietary DVR formats are reported as unsupported unless a validated vendor parser is implemented. Current Dahua, Hikvision, CP Plus, Uniview, Honeywell, and Matrix adapters provide the parser contract and safe unsupported responses; they do not fabricate proprietary filesystem results.

FFmpeg and FFprobe are optional runtime dependencies for media extraction and rich video metadata. Missing binaries produce explicit unsupported or incomplete metadata results.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the OpenAPI UI.

Run tests with:

```powershell
python -m pytest -q
```

The initial implementation uses SQLite by default. Set `DATABASE_URL` to use another SQLAlchemy-compatible database.
