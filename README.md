# 🛡️ Aegis Scanner - AI Threat Intelligence Platform

**Live Demo:** [https://aegis-scanner.vercel.app](https://aegis-scanner.vercel.app)  
**Live API Docs:** [https://aegis-scanner.onrender.com/docs](https://aegis-scanner.onrender.com/docs)

Aegis Scanner is a full-stack cybersecurity tool designed to detect malware, phishing, and "typosquatting" attacks targeting AI users. It combines real-time threat intelligence with a custom heuristic engine to scan both URLs and Files.

## 🚀 Features
* **Real-Time Scanning:** Analyzes URLs against the **VirusTotal API** (70+ security vendors).
* **File & PDF Inspection:** Deep-scans files for hidden malware and extracts embedded phishing links from PDFs.
* **Automated Email Alerts:** Instantly notifies admins via **Resend API** when high-risk threats are detected.
* **AI Impersonation Detection:** Custom heuristics to catch fake "ChatGPT", "Midjourney", or "Sora" sites.
* **Scan History:** Persists all scan results to a cloud **PostgreSQL** database.

## 🛠️ Tech Stack
* **Frontend:** Next.js 14, Tailwind CSS, Lucide Icons (Deployed on Vercel)
* **Backend:** Python FastAPI, SQLAlchemy, Pydantic (Deployed on Render)
* **Engine:** Docker, Puppeteer (Headless Chrome), Redis
* **Database:** PostgreSQL (Cloud Managed)

## ⚡ Getting Started (Local)
1.  **Clone the repo:**
    \`\`\`bash
    git clone https://github.com/SachinMyadam/aegis-scanner.git
    \`\`\`
2.  **Create a .env file:**
    \`\`\`env
    VIRUSTOTAL_API_KEY=your_key
    RESEND_API_KEY=your_key
    DATABASE_URL=postgresql://...
    \`\`\`
3.  **Run with Docker:**
    \`\`\`bash
    docker compose up --build
    \`\`\`
