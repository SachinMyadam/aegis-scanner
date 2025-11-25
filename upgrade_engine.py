import os

# This is the new, intelligent Engine code that queries VirusTotal
engine_code = r'''import os
import base64
import httpx
import validators
import whois
import datetime
import tldextract
from urllib.parse import urlparse
from typing import Dict, Any, List

from .models import ScanRequest, ScanResult, ExternalReport, HeuristicResult, SandboxReport, Verdict
from .sandbox_manager import run_sandbox_scan as run_isolated_scan

OFFICIAL_AI_DOMAINS = {
    "chatgpt": "openai.com",
    "midjourney": "midjourney.com",
    "sora": "openai.com",
    "claude": "anthropic.com",
    "jasper": "jasper.ai",
}

class ThreatAggregationEngine:
    def __init__(self):
        self.max_risk_score = 100
        self.initial_risk_score = 0
        # Load API key from environment
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        
    async def scan_url(self, scan_request: ScanRequest) -> ScanResult:
        url = str(scan_request.url)
        risk_score = self.initial_risk_score
        heuristic_results: List[HeuristicResult] = []
        external_reports: List[ExternalReport] = []
        
        # 1. Whitelist Check
        is_whitelisted, _ = self._check_whitelist(url)
        if is_whitelisted:
            return ScanResult(
                input_url=url,
                final_verdict="Safe",
                risk_score=0,
                is_whitelisted=True,
                heuristic_results=[],
                external_reports=[],
                sandbox_report=SandboxReport(status="skipped", screenshot_path="")
            )
            
        # 2. Run Custom Heuristics
        domain = urlparse(url).netloc
        domain_heuristics = await self._run_domain_heuristics(domain)
        for hr in domain_heuristics:
            risk_score += hr.score_change
        heuristic_results.extend(domain_heuristics)
            
        # 3. Query External APIs (REAL VirusTotal)
        vt_report = await self._query_virustotal(url)
        external_reports.append(vt_report)
        
        # Increase score based on VT results
        vt_malicious = vt_report.data.get("malicious", 0)
        if vt_malicious > 0:
            risk_score += (vt_malicious * 10) # +10 score for every vendor that flags it
            
        # 4. Run Sandbox Scan
        sandbox_report = await run_isolated_scan(url)
        
        # 5. Final Verdict
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

    def _check_whitelist(self, url: str) -> tuple[bool, Verdict]:
        try:
            domain = urlparse(url).netloc
            extracted = tldextract.extract(domain)
            domain_root = f"{extracted.domain}.{extracted.suffix}"
            if domain_root in OFFICIAL_AI_DOMAINS.values():
                return True, "Safe"
            return False, "Suspicious"
        except:
            return False, "Suspicious"

    async def _run_domain_heuristics(self, domain: str) -> List[HeuristicResult]:
        results = []
        results.append(await self._check_typosquatting(domain))
        results.append(await self._check_domain_age(domain))
        return results

    async def _check_typosquatting(self, domain: str) -> HeuristicResult:
        is_triggered = False
        score_change = 0
        domain_name = tldextract.extract(domain).domain
        
        # Check for suspicious AI keywords in non-official domains
        if any(x in domain_name.lower() for x in ["chatgpt", "openai", "midjourney", "gpt-4"]):
            is_triggered = True
            score_change = 40
            description = "High Risk: Domain uses trademarked AI keywords but is not official."
        else:
            description = "Domain branding appears neutral."

        return HeuristicResult(name="Typosquatting Detection", is_triggered=is_triggered, score_change=score_change, description=description)

    async def _check_domain_age(self, domain: str) -> HeuristicResult:
        # Simplified for speed/stability in this demo
        return HeuristicResult(name="Domain Age Check", is_triggered=False, score_change=0, description="Skipped for performance")

    async def _query_virustotal(self, url: str) -> ExternalReport:
        """Queries the actual VirusTotal v3 API."""
        if not self.vt_api_key:
            return ExternalReport(source="VirusTotal", status="skipped", data={"error": "No API Key"})

        try:
            # VT requires the URL to be Base64 encoded (no padding)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.vt_api_key}
            
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return ExternalReport(source="VirusTotal", status="ok", data=stats)
            elif response.status_code == 404:
                return ExternalReport(source="VirusTotal", status="ok", data={"info": "URL not found in database (Fresh URL)"})
            else:
                return ExternalReport(source="VirusTotal", status="error", data={"code": response.status_code})
                
        except Exception as e:
            return ExternalReport(source="VirusTotal", status="error", data={"error": str(e)})

    def _determine_verdict(self, score: int, external: List) -> Verdict:
        # Immediate Fail if VirusTotal flags it
        for r in external:
            if r.source == "VirusTotal" and r.data.get("malicious", 0) >= 2:
                return "Malicious"
        
        if score >= 60: return "Malicious"
        elif score >= 20: return "Suspicious"
        return "Safe"
'''

# Write the new engine code
with open("backend/src/engine.py", "w") as f:
    f.write(engine_code)

print("Success! Engine upgraded with Real VirusTotal Logic.")
