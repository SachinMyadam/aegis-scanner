import os
import requests
from .models import ScanResult

class EmailManager:
    def __init__(self):
        # Use Resend API to bypass Render's SMTP port block
        self.api_key = os.getenv("RESEND_API_KEY")
        self.recipient_email = os.getenv("ALERT_RECIPIENT_EMAIL")
        self.api_url = "https://api.resend.com/emails"

    def send_alert(self, result: ScanResult):
        if not self.api_key:
            print("⚠️ Resend API Key missing. Skipping email.")
            return

        if result.final_verdict != "Malicious":
            return

        subject = f"🚨 AEGIS ALERT: Malicious Threat Detected ({result.risk_score}/100)"
        
        body = f"""
        ⚠️ High Risk Threat Detected!
        
        Target: {result.input_url}
        Verdict: {result.final_verdict.upper()}
        Risk Score: {result.risk_score}/100
        
        --- Intelligence Summary ---
        """
        
        for report in result.external_reports:
            if report.source == "VirusTotal":
                malicious = report.data.get('malicious', 0)
                body += f"\nVirusTotal Detections: {malicious}"

        # Resend API Payload
        payload = {
            "from": "onboarding@resend.dev",
            "to": [self.recipient_email],
            "subject": subject,
            "text": body
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(self.api_url, json=payload, headers=headers)
            if response.ok:
                print(f"✅ Alert email sent via Resend to {self.recipient_email}")
            else:
                print(f"❌ Resend API Error: {response.text}")
        except Exception as e:
            print(f"❌ Connection Error: {str(e)}")
