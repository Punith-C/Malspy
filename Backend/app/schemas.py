
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr

class AnalyzeResponse(BaseModel):
    verdict: str
    risk_score: float
    features: Dict[str, Any]
    explain: str

# app/schemas.py
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

class UserResponse(BaseModel):
    id: int
    name: str
    phone: str
    email: str
    gender: str
    terms_accepted: bool

    class Config:
        orm_mode = True
