import smtplib
import os
from email.message import EmailMessage
from .models import ScanResult

class EmailManager:
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        # FIX: Switch to Port 465 (SSL) which is more reliable in Cloud
        self.smtp_port = 465
        self.sender_email = os.getenv("SMTP_EMAIL")
        self.sender_password = os.getenv("SMTP_PASSWORD")
        self.recipient_email = os.getenv("ALERT_RECIPIENT_EMAIL")

    def send_alert(self, result: ScanResult):
        if not self.sender_email or not self.sender_password:
            print("Email alerts not configured. Skipping.")
            return

        if result.final_verdict != "Malicious":
            return

        msg = EmailMessage()
        msg['Subject'] = f"🚨 AEGIS ALERT: Malicious Threat Detected ({result.risk_score}/100)"
        msg['From'] = self.sender_email
        msg['To'] = self.recipient_email

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

        body += "\n\n--- Heuristics Triggered ---"
        for heuristic in result.heuristic_results:
            if heuristic.is_triggered:
                body += f"\n- {heuristic.name}: {heuristic.description}"

        msg.set_content(body)

        try:
            # FIX: Use SMTP_SSL directly (No starttls needed)
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            print(f"✅ Alert email sent to {self.recipient_email}")
        except Exception as e:
            print(f"❌ Failed to send email alert: {str(e)}")
