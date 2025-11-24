
# Hybrid Malware Scanner – Backend (FastAPI)

A minimal, **working** backend for your Android malware detection app.  
It performs **static analysis** on uploaded APKs using **Androguard**, computes a quick risk score, and returns a JSON verdict.

> This is an MVP you can demo tomorrow. It focuses on static analysis (permissions, intent filters, dangerous API patterns). Dynamic analysis hooks are stubbed for later.

## 1) Quick Start (no Docker)

> Requires Python 3.10+ and Java (for some APK parsing environments). Linux/Mac/WSL recommended.

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

# run dev server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open: http://localhost:8000/docs

Upload an APK with the `/analyze` endpoint.

## 2) With Docker (optional)

```bash
docker build -t hybrid-scanner .
docker run --rm -p 8000:8000 hybrid-scanner
```

## 3) Endpoints

- `POST /analyze` – multipart upload of an APK (`file` field). Returns:
  ```json
  {
    "verdict": "malicious|benign|suspicious",
    "risk_score": 0.0-1.0,
    "features": { ... },
    "explain": "human-readable reasons"
  }
  ```
- `GET /health` – liveness check

## 4) Project Layout

```
app/
  main.py           # FastAPI app
  analyzer.py       # Static analyzer with Androguard
  risk_model.py     # Simple rule-based risk model (MVP)
  schemas.py        # Pydantic models
  utils.py          # Helpers
requirements.txt
Dockerfile
README.md
```

## 5) Notes

- This MVP uses **rule-based scoring**. You can plug in ML later by saving features and training a classifier (Scikit-learn/XGBoost).
- If Androguard fails to parse an APK, verify Java is installed and that the APK is not heavily obfuscated or corrupted.
- For dynamic analysis, integrate DroidBox or an emulator later and POST the runtime JSON to a `/dynamic` endpoint to merge scores.
