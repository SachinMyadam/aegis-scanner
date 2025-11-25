from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List

from .models import ScanRequest, ScanResult
from .engine import ThreatAggregationEngine
from .database import SessionLocal, init_db, ScanRecord

# Initialize Database Tables
init_db()

app = FastAPI(title="Threat Intelligence API")

# Allow Frontend Connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ThreatAggregationEngine()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/api/v1/scan/url", response_model=ScanResult)
async def scan_url(scan_request: ScanRequest, db: Session = Depends(get_db)):
    # 1. Run the Scan
    result = await engine.scan_url(scan_request)
    
    # 2. Save to Database
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
    db.refresh(db_record)
    
    return result

@app.get("/api/v1/history")
async def get_history(limit: int = 10, db: Session = Depends(get_db)):
    """Fetch the last 10 scans."""
    scans = db.query(ScanRecord).order_by(ScanRecord.id.desc()).limit(limit).all()
    return scans
