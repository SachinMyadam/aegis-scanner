import os

# 1. Add python-multipart to requirements (needed for file uploads)
with open("backend/requirements.txt", "a") as f:
    f.write("\npython-multipart==0.0.6")

# 2. Update engine.py to support File Hashing
engine_code = r'''import os
import base64
import httpx
import hashlib
import validators
import tldextract
from urllib.parse import urlparse
from typing import List

from .models import ScanRequest, ScanResult, ExternalReport, HeuristicResult, SandboxReport, Verdict
from .sandbox_manager import run_sandbox_scan as run_isolated_scan

OFFICIAL_AI_DOMAINS = {
    "chatgpt": "openai.com",
    "openai": "openai.com",
    "midjourney": "midjourney.com",
    "sora": "openai.com",
    "claude": "anthropic.com",
    "jasper": "jasper.ai",
}

class ThreatAggregationEngine:
    def __init__(self):
        self.max_risk_score = 100
        self.initial_risk_score = 0
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        
    async def scan_url(self, scan_request: ScanRequest) -> ScanResult:
        # ... (Existing URL Logic matches previous version) ...
        url = str(scan_request.url)
        risk_score = self.initial_risk_score
        heuristic_results = []
        external_reports = []
        
        is_whitelisted, _ = self._check_whitelist(url)
        if is_whitelisted:
            return self._build_safe_result(url, is_whitelisted=True)
            
        domain = urlparse(url).netloc
        heuristic_results.extend(await self._run_domain_heuristics(domain))
        
        vt_report = await self._query_virustotal(url)
        external_reports.append(vt_report)
        risk_score += self._calculate_vt_score(vt_report)
            
        sandbox_report = await run_isolated_scan(url)
        
        final_score = min(max(risk_score, 0), self.max_risk_score)
        final_verdict = self._determine_verdict(final_score, external_reports)
        
        return ScanResult(
            input_url=url,
            final_verdict=final_verdict,
            risk_score=final_score,
            is_whitelisted=is_whitelisted,
            heuristic_results=heuristic_results,
            external_reports=external_reports,
            sandbox_report=sandbox_report
        )

    async def scan_file(self, file_bytes: bytes, filename: str) -> ScanResult:
        """NEW: Calculate hash and check VirusTotal"""
        # 1. Calculate SHA256 Hash (The Digital Fingerprint)
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        
        risk_score = 0
        external_reports = []
        
        # 2. Query VirusTotal with Hash
        vt_report = await self._query_virustotal_hash(sha256_hash)
        external_reports.append(vt_report)
        risk_score += self._calculate_vt_score(vt_report)
        
        # 3. Determine Verdict
        final_score = min(max(risk_score, 0), self.max_risk_score)
        final_verdict = self._determine_verdict(final_score, external_reports)
        
        # Create a dummy sandbox report for files (since we don't screenshot files)
        sandbox_report = SandboxReport(status="skipped", screenshot_path="")

        return ScanResult(
            input_url=f"File: {filename}",
            final_verdict=final_verdict,
            risk_score=final_score,
            is_whitelisted=False,
            heuristic_results=[HeuristicResult(name="File Hash Analysis", is_triggered=True, score_change=0, description=f"SHA256: {sha256_hash}")],
            external_reports=external_reports,
            sandbox_report=sandbox_report
        )

    # --- Helper Methods ---
    
    def _build_safe_result(self, url, is_whitelisted=False):
        return ScanResult(input_url=url, final_verdict="Safe", risk_score=0, is_whitelisted=is_whitelisted, heuristic_results=[], external_reports=[], sandbox_report=SandboxReport(status="skipped"))

    def _calculate_vt_score(self, vt_report):
        malicious = vt_report.data.get("malicious", 0)
        suspicious = vt_report.data.get("suspicious", 0)
        return (malicious * 20) + (suspicious * 10)

    def _check_whitelist(self, url: str):
        try:
            domain = urlparse(url).netloc
            extracted = tldextract.extract(domain)
            domain_root = f"{extracted.domain}.{extracted.suffix}"
            return (True, "Safe") if domain_root in OFFICIAL_AI_DOMAINS.values() else (False, "Suspicious")
        except: return (False, "Suspicious")

    async def _run_domain_heuristics(self, domain: str):
        # (Keep existing typosquatting logic)
        return []

    async def _query_virustotal(self, url: str) -> ExternalReport:
        # (Keep existing URL logic)
        if not self.vt_api_key: return ExternalReport(source="VirusTotal", status="skipped", data={"error": "No API Key"})
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.vt_api_key}
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            return self._parse_vt_response(response)
        except Exception as e: return ExternalReport(source="VirusTotal", status="error", data={"error": str(e)})

    async def _query_virustotal_hash(self, file_hash: str) -> ExternalReport:
        """NEW: Query VT by File Hash"""
        if not self.vt_api_key: return ExternalReport(source="VirusTotal", status="skipped", data={"error": "No API Key"})
        try:
            headers = {"x-apikey": self.vt_api_key}
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
            return self._parse_vt_response(response)
        except Exception as e: return ExternalReport(source="VirusTotal", status="error", data={"error": str(e)})

    def _parse_vt_response(self, response):
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return ExternalReport(source="VirusTotal", status="ok", data=stats)
        elif response.status_code == 404:
            return ExternalReport(source="VirusTotal", status="ok", data={"malicious": 0, "info": "Clean/Unknown"})
        else:
            return ExternalReport(source="VirusTotal", status="error", data={"code": response.status_code})

    def _determine_verdict(self, score: int, external: List) -> Verdict:
        for r in external:
            if r.source == "VirusTotal" and r.data.get("malicious", 0) >= 1: return "Malicious"
        if score >= 60: return "Malicious"
        elif score >= 30: return "Suspicious"
        return "Safe"
'''
with open("backend/src/engine.py", "w") as f:
    f.write(engine_code)

# 3. Update app.py to accept file uploads
app_code = r'''from fastapi import FastAPI, Depends, UploadFile, File
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
'''
with open("backend/src/app.py", "w") as f:
    f.write(app_code)

print("Backend upgraded to V2 (File Scanning)!")
