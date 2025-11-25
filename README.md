# 🛡️ Aegis Scanner - AI Threat Intelligence Platform

Aegis Scanner is a full-stack cybersecurity tool designed to detect malware, phishing, and "typosquatting" attacks targeting AI users. It combines real-time threat intelligence with a custom heuristic engine.

## 🚀 Features
* **Real-Time Scanning:** Analyzes URLs against the **VirusTotal API** (70+ security vendors).
* **AI Impersonation Detection:** Custom heuristics to catch fake "ChatGPT", "Midjourney", or "Sora" sites.
* **Sandbox Isolation:** Runs a **Headless Chrome Browser** inside a secure Docker container to safe-visit and screenshot malicious sites.
* **Scan History:** Persists all scan results to a **PostgreSQL** database.

## 🛠️ Tech Stack
* **Frontend:** Next.js 14, Tailwind CSS, Lucide Icons
* **Backend:** Python FastAPI, SQLAlchemy, Pydantic
* **Engine:** Docker, Puppeteer (Headless Chrome), Redis
* **Database:** PostgreSQL

## ⚡ Getting Started (Local)
1.  Clone the repo:
    ```bash
    git clone [https://github.com/SachinMyadam/aegis-scanner.git](https://github.com/SachinMyadam/aegis-scanner.git)
    ```
2.  Create a `.env` file in the root with your keys:
    ```env
    VIRUSTOTAL_API_KEY=your_key_here
    DATABASE_URL=postgresql://scanner_user:scanner_password@db:5432/threat_db
    ```
3.  Run with Docker:
    ```bash
    docker compose up --build
    ```
4.  Open the dashboard at `http://localhost:3001`
