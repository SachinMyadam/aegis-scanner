from pydantic import BaseModel, HttpUrl
from typing import Literal, List, Dict, Any

# --- Request Models ---

class ScanRequest(BaseModel):
    """Model for the incoming URL scan request."""
    url: HttpUrl
    client_ip: str

# --- Result Models ---

Verdict = Literal["Safe", "Suspicious", "Malicious"]

class HeuristicResult(BaseModel):
    """Details for a single custom heuristic check."""
    name: str
    is_triggered: bool
    score_change: int
    description: str

class ExternalReport(BaseModel):
    """Summary of data from external APIs like VirusTotal."""
    source: str
    status: Literal["ok", "error", "skipped"]
    data: Dict[str, Any]

class SandboxReport(BaseModel):
    """Data captured from the isolated headless browser scan."""
    # FIX: Added "skipped" to the allowed list below
    status: Literal["ok", "error", "skipped"]
    screenshot_path: str = "" 
    dom_hash: str = ""
    malicious_scripts_detected: bool = False

class ScanResult(BaseModel):
    """The complete response model for a URL scan."""
    input_url: str
    final_verdict: Verdict
    risk_score: int 
    is_whitelisted: bool
    
    # Detailed Reports
    heuristic_results: List[HeuristicResult]
    external_reports: List[ExternalReport]
    sandbox_report: SandboxReport
