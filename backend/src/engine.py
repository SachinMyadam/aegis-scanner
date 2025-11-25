import os
import base64
import httpx
import validators
import tldextract
from urllib.parse import urlparse
from typing import List

from .models import ScanRequest, ScanResult, ExternalReport, HeuristicResult, SandboxReport, Verdict
from .sandbox_manager import run_sandbox_scan as run_isolated_scan
from .database import SessionLocal, ScanRecord

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
            
        # 3. Query External APIs (VirusTotal)
        vt_report = await self._query_virustotal(url)
        external_reports.append(vt_report)
        
        vt_malicious = vt_report.data.get("malicious", 0)
        vt_suspicious = vt_report.data.get("suspicious", 0)
        
        if vt_malicious > 0:
            risk_score += (vt_malicious * 20) 
        if vt_suspicious > 0:
            risk_score += (vt_suspicious * 10)
            
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
        return results

    async def _check_typosquatting(self, domain: str) -> HeuristicResult:
        is_triggered = False
        score_change = 0
        
        # Extract the "name" part of the domain (e.g., "chat-gpt-login")
        domain_part = tldextract.extract(domain).domain.lower()
        
        # IMPROVED LIST: Catches "chat-gpt", "chatgpt", "open-ai", "mid-journey"
        suspicious_keywords = [
            "chatgpt", "chat-gpt", 
            "openai", "open-ai", 
            "midjourney", "mid-journey",
            "gpt-4", "gpt4",
            "sora-ai", "sora"
        ]
        
        if any(keyword in domain_part for keyword in suspicious_keywords):
            is_triggered = True
            score_change = 75 # High penalty for faking AI brands
            description = f"High Risk: Domain '{domain_part}' attempts to impersonate an AI brand."
        else:
            description = "Domain branding appears neutral."

        return HeuristicResult(name="Typosquatting Detection", is_triggered=is_triggered, score_change=score_change, description=description)

    async def _query_virustotal(self, url: str) -> ExternalReport:
        if not self.vt_api_key:
            return ExternalReport(source="VirusTotal", status="skipped", data={"error": "No API Key"})

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.vt_api_key}
            
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return ExternalReport(source="VirusTotal", status="ok", data=stats)
            elif response.status_code == 404:
                return ExternalReport(source="VirusTotal", status="ok", data={"malicious": 0, "suspicious": 0, "info": "Fresh URL"})
            else:
                return ExternalReport(source="VirusTotal", status="error", data={"code": response.status_code})
        except Exception as e:
            return ExternalReport(source="VirusTotal", status="error", data={"error": str(e)})

    def _determine_verdict(self, score: int, external: List) -> Verdict:
        # If VT says it's bad, IT IS BAD.
        for r in external:
            if r.source == "VirusTotal" and r.data.get("malicious", 0) >= 1:
                return "Malicious"
        
        if score >= 60: return "Malicious"
        elif score >= 30: return "Suspicious"
        return "Safe"
