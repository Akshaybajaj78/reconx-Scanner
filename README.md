# ReconX CLI

Terminal-based automated reconnaissance and vulnerability scanner for academic use.

## Features
- Port scanning (top 1000 ports via nmap)
- Subdomain scanning (small built-in wordlist)
- Directory scanning (from `wordlist.txt`)
- HTTP header security checks
- CORS misconfiguration checks
- Basic XSS reflection test
- PDF report generation

## Setup
1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Ensure Nmap is installed and available in your PATH.

## Run
```bash
python reconx.py example.com
```

## Run Web UI
1. Build React frontend:
```bash
cd frontend
npm install
npm run build
cd ..
```

2. Start Flask:
```bash
python app.py
```
Then open `http://127.0.0.1:5000` in your browser.

### Frontend Dev Mode (optional)
Terminal 1:
```bash
python app.py
```

Terminal 2:
```bash
cd frontend
npm install
npm run dev
```
Open the URL shown by Vite (usually `http://127.0.0.1:5173`).

Optional arguments:
- `--wordlist path/to/wordlist.txt`
- `--report reconx_report.pdf`
- `--timeout 5`

## Notes
- This tool is intended for academic, authorized testing only.
- Some scans may require permissions or be blocked by target defenses.

## Deploy (Render backend + Vercel frontend)

### 1) Deploy backend to Render
- Create a new **Web Service** from this repo.
- Use **Docker** environment (Render will use `Dockerfile`).
- Add environment variable:
  - `CORS_ALLOWED_ORIGINS=https://your-frontend.vercel.app`
- Deploy and copy backend URL (example: `https://reconx-backend.onrender.com`).

### 2) Deploy frontend to Vercel
- Set Vercel project root to `frontend`.
- Add environment variable:
  - `VITE_API_BASE=https://your-render-backend.onrender.com`
- Redeploy frontend.

### 3) Verify
- Open frontend URL.
- Click **Start Scan**.
- In browser network tab, verify request goes to:
  - `https://your-render-backend.onrender.com/api/scan`
