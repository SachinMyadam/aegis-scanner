import os

app_py_content = """from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .models import ScanRequest, ScanResult
from .engine import ThreatAggregationEngine

app = FastAPI(title="Threat Intelligence & URL Verification API")

# FIX: Allow Frontend (Port 3000) to communicate with Backend (Port 8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, change this to ["http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ThreatAggregationEngine()

@app.get("/health", response_class=JSONResponse)
async def health_check():
    return {"status": "ok", "service": "threat-scanner-api"}

@app.post("/api/v1/scan/url", response_model=ScanResult)
async def scan_url(scan_request: ScanRequest):
    # We pass the user's scan request to the engine
    result = await engine.scan_url(scan_request)
    return result
"""

with open("backend/src/app.py", "w") as f:
    f.write(app_py_content)

print("Success: CORS Middleware added to Backend.")
