import httpx
from .models import SandboxReport

# The internal Docker DNS hostname for the sandbox service
SANDBOX_URL = "http://sandbox:3000/scan"

async def run_sandbox_scan(url: str) -> SandboxReport:
    """
    Sends the URL to the Sandbox Microservice via HTTP and awaits the result.
    """
    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(SANDBOX_URL, json={"url": url})
            
            if response.status_code != 200:
                return SandboxReport(
                    status="error", 
                    error=f"Sandbox service returned {response.status_code}"
                )
            
            report_data = response.json()
            
            if report_data.get("status") == "ok":
                return SandboxReport(
                    status="ok",
                    screenshot_path=f"data:image/jpeg;base64,{report_data.get('screenshot_base64', '')}",
                    dom_hash=report_data.get('dom_hash', ''),
                    malicious_scripts_detected=report_data.get('malicious_scripts_detected', False)
                )
            else:
                return SandboxReport(
                    status="error",
                    error=report_data.get("error", "Unknown sandbox error")
                )

    except httpx.TimeoutException:
        return SandboxReport(status="error", error="Sandbox scan timed out.")
    except httpx.RequestError as e:
        return SandboxReport(status="error", error=f"Connection to sandbox failed: {str(e)}")
    except Exception as e:
        return SandboxReport(status="error", error=f"Unexpected error: {str(e)}")
