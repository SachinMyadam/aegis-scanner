import os
import base64
import httpx
import hashlib
import io
import re
import pypdf
import tldextract
from urllib.parse import urlparse
from typing import List

from .models import ScanRequest, ScanResult, ExternalReport, HeuristicResult, SandboxReport, Verdict
# Re-enable the Sandbox
from .sandbox_manager import run_sandbox_scan as run_isolated_scan
from .email_manager import EmailManager

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
        self.email_manager = EmailManager()
        
    async def scan_url(self, scan_request: ScanRequest) -> ScanResult:
        url = str(scan_request.url)
        result = await self._perform_full_url_scan(url)
        
        if result.final_verdict == "Malicious":
            self.email_manager.send_alert(result)
            
        return result

    async def scan_file(self, file_bytes: bytes, filename: str) -> ScanResult:
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        risk_score = 0
        heuristic_results = []
        external_reports = []
        
        vt_report = await self._query_virustotal_hash(sha256_hash)
        external_reports.append(vt_report)
        risk_score += self._calculate_vt_score(vt_report)
        
        heuristic_results.append(HeuristicResult(name="File Hash Analysis", is_triggered=True, score_change=0, description=f"SHA256: {sha256_hash}"))

        if filename.lower().endswith(".pdf"):
            pdf_score, pdf_heuristics = await self._analyze_pdf_content(file_bytes)
            risk_score += pdf_score
            heuristic_results.extend(pdf_heuristics)

        final_score = min(max(risk_score, 0), self.max_risk_score)
        final_verdict = self._determine_verdict(final_score, external_reports)
        
        # Files don't get screenshots, so we skip sandbox here
        result = ScanResult(
            input_url=f"File: {filename}",
            final_verdict=final_verdict,
            risk_score=final_score,
            is_whitelisted=False,
            heuristic_results=heuristic_results,
            external_reports=external_reports,
            sandbox_report=SandboxReport(status="skipped", screenshot_path="")
        )
        
        if result.final_verdict == "Malicious":
            self.email_manager.send_alert(result)
            
        return result

    # --- Internal Logic ---

    async def _perform_full_url_scan(self, url):
        risk_score = self.initial_risk_score
        heuristic_results = []
        external_reports = []
        
        is_whitelisted, _ = self._check_whitelist(url)
        if is_whitelisted:
            return self._build_safe_result(url, is_whitelisted=True)
            
        domain = urlparse(url).netloc
        heuristic_results.extend(await self._run_domain_heuristics(domain))
        
        # Run Aggressive Keyword Check
        keyword_score, keyword_heuristics = await self._check_aggressive_keywords(domain)
        risk_score += keyword_score
        heuristic_results.extend(keyword_heuristics)
        
        vt_report = await self._query_virustotal(url)
        external_reports.append(vt_report)
        risk_score += self._calculate_vt_score(vt_report)
            
        # RESTORED: The Full Sandbox Scan (Screenshots enabled)
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

    async def _check_aggressive_keywords(self, domain: str):
        score = 0
        results = []
        domain_lower = domain.lower()
        bad_keywords = ["ibomma", "tamil", "movie", "stream", "free-download", "crack", "hack", "cheat", "betting", "casino"]
        found_words = [word for word in bad_keywords if word in domain_lower]
        if found_words:
            score += 40 
            results.append(HeuristicResult(name="Aggressive Keyword Scan", is_triggered=True, score_change=40, description=f"Risk keywords: {', '.join(found_words)}"))
        return score, results

    async def _analyze_pdf_content(self, file_bytes):
        score = 0
        results = []
        try:
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            text_content = ""
            for page in reader.pages:
                text_content += page.extract_text() + "\n"
            
            urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text_content)
            
            if urls:
                results.append(HeuristicResult(name="PDF Structure", is_triggered=True, score_change=0, description=f"Found {len(urls)} embedded links."))
                for link in urls[:3]:
                    vt_report = await self._query_virustotal(link)
                    if vt_report.data.get("malicious", 0) > 0:
                        score += 75
                        results.append(HeuristicResult(name="Malicious PDF Link", is_triggered=True, score_change=75, description=f"Embedded URL flagged: {link}"))
            else:
                results.append(HeuristicResult(name="PDF Structure", is_triggered=False, score_change=0, description="No embedded links found."))
                
        except Exception as e:
            results.append(HeuristicResult(name="PDF Analysis", is_triggered=True, score_change=20, description=f"Failed to parse PDF: {str(e)}"))
            score += 20
            
        return score, results

    def _build_safe_result(self, url, is_whitelisted=False):
        return ScanResult(input_url=url, final_verdict="Safe", risk_score=0, is_whitelisted=is_whitelisted, heuristic_results=[], external_reports=[], sandbox_report=SandboxReport(status="skipped"))

    def _calculate_vt_score(self, vt_report):
        return (vt_report.data.get("malicious", 0) * 20) + (vt_report.data.get("suspicious", 0) * 10)

    def _check_whitelist(self, url: str):
        try:
            domain = urlparse(url).netloc
            extracted = tldextract.extract(domain)
            domain_root = f"{extracted.domain}.{extracted.suffix}"
            return (True, "Safe") if domain_root in OFFICIAL_AI_DOMAINS.values() else (False, "Suspicious")
        except: return (False, "Suspicious")

    async def _run_domain_heuristics(self, domain: str) -> List[HeuristicResult]:
        results = []
        results.append(await self._check_typosquatting(domain))
        return results

    async def _check_typosquatting(self, domain: str) -> HeuristicResult:
        is_triggered = False
        score_change = 0
        domain_part = tldextract.extract(domain).domain.lower()
        suspicious_keywords = ["chatgpt", "chat-gpt", "openai", "open-ai", "midjourney", "gpt-4"]
        if any(keyword in domain_part for keyword in suspicious_keywords):
            is_triggered = True
            score_change = 75
            description = f"High Risk: Domain '{domain_part}' attempts to impersonate an AI brand."
        else:
            description = "Domain branding appears neutral."
        return HeuristicResult(name="Typosquatting Detection", is_triggered=is_triggered, score_change=score_change, description=description)

    async def _query_virustotal(self, url: str) -> ExternalReport:
        if not self.vt_api_key: return ExternalReport(source="VirusTotal", status="skipped", data={"error": "No API Key"})
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.vt_api_key}
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            return self._parse_vt_response(response)
        except Exception as e: return ExternalReport(source="VirusTotal", status="error", data={"error": str(e)})

    async def _query_virustotal_hash(self, file_hash: str) -> ExternalReport:
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
