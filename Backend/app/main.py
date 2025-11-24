from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Dict, Any
import traceback
import json
import os

# -------------------------------
# Local imports (relative)
# -------------------------------
from .analyzer import extract_static_features, analyze_dynamic_features, determine_action
from .ml_model import load_model, model_exists, extract_vector
from .utils import TempFile

# -------------------------------
# Init app
# -------------------------------
app = FastAPI(title="Hybrid Malware Scanner (MVP)", version="1.0.0")

MODEL = load_model() if model_exists() else None

# -------------------------------
# User DB (JSON file storage)
# -------------------------------
USERS_FILE = "users.json"
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, "r") as f:
        users_db = json.load(f)
else:
    users_db = {}

class UserSignup(BaseModel):
    name: str
    phone: str
    email: EmailStr
    password: str
    gender: str
    terms_accepted: bool

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# -------------------------------
# Health check
# -------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": MODEL is not None}

# -------------------------------
# Auth routes
# -------------------------------
@app.post("/signup")
def signup(user: UserSignup):
    if not user.terms_accepted:
        raise HTTPException(status_code=400, detail="You must accept terms and conditions")
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    users_db[user.email] = {
        "name": user.name,
        "phone": user.phone,
        "password": user.password,
        "gender": user.gender,
        "terms_accepted": user.terms_accepted,
    }
    with open(USERS_FILE, "w") as f:
        json.dump(users_db, f, indent=4)
    return {"message": "Signup successful"}

@app.post("/login")
def login(user: UserLogin):
    db_user = users_db.get(user.email)
    if not db_user or db_user["password"] != user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Login successful"}

@app.get("/users")
def list_users():
    return users_db

# -------------------------------
# Static Analysis
# -------------------------------
@app.post("/analyze/static")
async def analyze_static(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Please upload an .apk file")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file received")

    with TempFile(suffix=".apk") as tmp:
        tmp.write_bytes(content)
        try:
            feats = extract_static_features(str(tmp))
            n_dangerous_perms = sum(
                1 for p in feats.get("permissions", [])
                if any(x in p for x in ["SMS", "CALL", "INTERNET", "RECORD_AUDIO", "CAMERA"])
            )
            n_suspicious_apis = len(feats.get("suspicious_apis", []))
            risk_score = min(1.0, 0.2*n_dangerous_perms + 0.15*n_suspicious_apis)

            if risk_score < 0.2:
                verdict = "benign"
            elif risk_score < 0.4:
                verdict = "adware"
            elif risk_score < 0.6:
                verdict = "spyware"
            elif risk_score < 0.8:
                verdict = "trojan"
            else:
                verdict = "ransomware"

            action = determine_action(verdict, risk_score)

        except Exception as e:
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Static analysis failed: {e}")

    return {
        "analysis_type": "static",
        "verdict": verdict,
        "risk_score": risk_score,
        "recommended_action": action,
        "features": feats,
    }

# -------------------------------
# Dynamic Analysis
# -------------------------------
@app.post("/analyze/dynamic")
async def analyze_dynamic(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Please upload an .apk file")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file received")

    with TempFile(suffix=".apk") as tmp:
        tmp.write_bytes(content)
        try:
            dyn_logs = analyze_dynamic_features(str(tmp))
            n_network = len(dyn_logs.get("network_calls", []))
            n_syscalls = len(dyn_logs.get("system_calls", []))
            sms_used = dyn_logs.get("sms_used", False)
            risk_score = min(1.0, 0.2*n_network + 0.2*n_syscalls + (0.3 if sms_used else 0))

            if risk_score < 0.2:
                verdict = "benign"
            elif risk_score < 0.4:
                verdict = "adware"
            elif risk_score < 0.6:
                verdict = "spyware"
            elif risk_score < 0.8:
                verdict = "trojan"
            else:
                verdict = "ransomware"

            action = determine_action(verdict, risk_score)

        except Exception as e:
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Dynamic analysis failed: {e}")

    return {
        "analysis_type": "dynamic",
        "verdict": verdict,
        "risk_score": risk_score,
        "recommended_action": action,
        "logs": dyn_logs,
    }

# -------------------------------
# Hybrid Analysis
# -------------------------------
@app.post("/analyze/hybrid")
async def analyze_hybrid(file: UploadFile = File(...)):
    global MODEL
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Please upload an .apk file")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file received")

    with TempFile(suffix=".apk") as tmp:
        tmp.write_bytes(content)
        try:
            feats = extract_static_features(str(tmp))
            dyn_logs = analyze_dynamic_features(str(tmp))

            n_suspicious_apis = len(feats.get("suspicious_apis", []))
            n_dangerous_perms = sum(
                1 for p in feats.get("permissions", [])
                if any(x in p for x in ["SMS", "CALL", "INTERNET", "RECORD_AUDIO", "CAMERA"])
            )
            n_network = len(dyn_logs.get("network_calls", []))
            n_syscalls = len(dyn_logs.get("system_calls", []))
            sms_used = dyn_logs.get("sms_used", False)

            heuristic_score = min(
                1.0,
                0.15*n_dangerous_perms + 0.15*n_suspicious_apis +
                0.2*n_network + 0.2*n_syscalls + (0.2 if sms_used else 0)
            )

            if MODEL:
                vec = extract_vector(feats, dyn_logs)
                prob = float(MODEL.predict_proba([vec])[0][1])
                risk_score = prob
            else:
                risk_score = heuristic_score

            if risk_score < 0.2:
                verdict = "benign"
            elif risk_score < 0.4:
                verdict = "adware"
            elif risk_score < 0.6:
                verdict = "spyware"
            elif risk_score < 0.8:
                verdict = "trojan"
            else:
                verdict = "ransomware"

            action = determine_action(verdict, risk_score)
            style = {"color": "#4CAF50"} if verdict == "benign" else {"color": "#F44336"}

        except Exception as e:
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Hybrid analysis failed: {e}")

    return {
        "analysis_type": "hybrid",
        "verdict": verdict,
        "risk_score": risk_score,
        "recommended_action": action,
        "style": style,
        "static_features": feats,
        "dynamic_logs": dyn_logs,
    }
