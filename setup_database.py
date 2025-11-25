import os

# 1. Update requirements.txt to include SQLAlchemy
requirements_txt = """fastapi==0.104.1
uvicorn[standard]==0.24.0.post1
pydantic==2.5.2
python-dotenv==1.0.0
validators==0.22.0
python-whois==0.8.0
requests==2.31.0
dnspython==2.4.2
redis==5.0.1
psycopg2-binary==2.9.9
tldextract==5.1.1
httpx==0.27.0
sqlalchemy==2.0.23
"""

# 2. Create backend/src/database.py (Handles DB connection)
database_py = """from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

# Get DB URL from .env
DATABASE_URL = os.getenv("DATABASE_URL")

# Create Connection
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Define the "scans" table
class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    verdict = Column(String)
    risk_score = Column(Integer)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Store complex data (like heuristics) as JSON
    heuristic_data = Column(JSON)
    external_data = Column(JSON)
    screenshot_path = Column(String, nullable=True)

# Create tables
def init_db():
    Base.metadata.create_all(bind=engine)
"""

# 3. Update backend/src/app.py (Saves every scan to DB)
# We use single quotes ''' here to avoid conflict with the double quotes """ inside the code
app_py = '''from fastapi import FastAPI, Depends, HTTPException
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
'''

# Write files
file_map = {
    "backend/requirements.txt": requirements_txt,
    "backend/src/database.py": database_py,
    "backend/src/app.py": app_py,
}

print("Setting up Database persistence...")
for path, content in file_map.items():
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Updated: {path}")

print("Success! Database logic added.")
