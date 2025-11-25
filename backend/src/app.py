from fastapi import FastAPI, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .models import ScanRequest, ScanResult
from .engine import ThreatAggregationEngine
from .database import SessionLocal, init_db, ScanRecord

init_db()
app = FastAPI(title="Threat Intelligence API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ThreatAggregationEngine()

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

@app.post("/api/v1/scan/url", response_model=ScanResult)
async def scan_url(scan_request: ScanRequest, db: Session = Depends(get_db)):
    result = await engine.scan_url(scan_request)
    _save_to_db(db, result)
    return result

@app.post("/api/v1/scan/file", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """NEW Endpoint for File Scanning"""
    file_content = await file.read()
    result = await engine.scan_file(file_content, file.filename)
    _save_to_db(db, result)
    return result

def _save_to_db(db, result):
    db_record = ScanRecord(
        url=result.input_url,
        verdict=result.final_verdict,
        risk_score=result.risk_score,
        heuristic_data=[h.dict() for h in result.heuristic_results],
        external_data=[e.dict() for e in result.external_reports],
        screenshot_path=result.sandbox_report.screenshot_path if result.sandbox_report else ""
    )
    db.add(db_record)
    db.commit()

@app.get("/api/v1/history")
async def get_history(limit: int = 10, db: Session = Depends(get_db)):
    return db.query(ScanRecord).order_by(ScanRecord.id.desc()).limit(limit).all()
