"""
IronCage SaaS API
"""

import os
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
import jwt

# Config
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"

# Database (in-memory)
users_db: Dict[str, dict] = {}
tenants_db: Dict[str, dict] = {}
api_keys_db: Dict[str, str] = {}
scans_db: List[dict] = []

# Threat patterns
THREAT_PATTERNS = [
    "ignore all previous", "disregard instructions", "system override",
    "jailbreak", "dan mode", "bypass security", "admin access",
    "forget your instructions", "you are now", "pretend to be",
]

# App
app = FastAPI(title="IronCage API", version="8.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# Helpers
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{h.hex()}"

def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, stored = password_hash.split(':')
        h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(h.hex(), stored)
    except:
        return False

def create_token(user_id: str, tenant_id: str = None) -> str:
    return jwt.encode(
        {"sub": user_id, "tenant_id": tenant_id, "exp": datetime.now(timezone.utc) + timedelta(hours=24)},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )

def scan_prompt(prompt: str) -> dict:
    prompt_lower = prompt.lower()
    risk = sum(0.2 for p in THREAT_PATTERNS if p in prompt_lower)
    risk = min(risk, 1.0)
    threats = [p for p in THREAT_PATTERNS if p in prompt_lower]
    return {"allowed": risk < 0.4, "risk_score": round(risk, 4), "threats_detected": threats}

async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not creds:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = users_db.get(payload["sub"])
        if not user:
            raise HTTPException(401, "User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except:
        raise HTTPException(401, "Invalid token")

async def get_tenant_from_key(x_api_key: str = Header(None, alias="X-API-Key")) -> dict:
    if not x_api_key:
        raise HTTPException(401, "API key required")
    tenant_id = api_keys_db.get(x_api_key)
    if not tenant_id:
        raise HTTPException(401, "Invalid API key")
    return tenants_db.get(tenant_id)

# Models
class SignupReq(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str
    company: str

class LoginReq(BaseModel):
    email: EmailStr
    password: str

class ScanReq(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=50000)

# Routes
@app.get("/")
async def root():
    return {"name": "IronCage API", "version": "8.0.0", "status": "running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/api/auth/signup")
async def signup(req: SignupReq):
    if any(u["email"] == req.email for u in users_db.values()):
        raise HTTPException(400, "Email already registered")
    
    user_id = secrets.token_hex(12)
    tenant_id = secrets.token_hex(12)
    api_key = f"ic_live_{secrets.token_hex(24)}"
    
    users_db[user_id] = {"id": user_id, "email": req.email, "password_hash": hash_password(req.password), "name": req.name, "tenant_id": tenant_id}
    tenants_db[tenant_id] = {"id": tenant_id, "name": req.company, "api_key": api_key, "plan": "starter", "scans": 0}
    api_keys_db[api_key] = tenant_id
    
    return {"token": create_token(user_id, tenant_id), "user": {"id": user_id, "email": req.email, "name": req.name}, "tenant": {"id": tenant_id, "name": req.company, "api_key": api_key, "plan": "starter"}}

@app.post("/api/auth/login")
async def login(req: LoginReq):
    user = next((u for u in users_db.values() if u["email"] == req.email), None)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    tenant = tenants_db.get(user["tenant_id"])
    return {"token": create_token(user["id"], user["tenant_id"]), "user": {"id": user["id"], "email": user["email"], "name": user["name"]}, "tenant": tenant}

@app.get("/api/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"user": user, "tenant": tenants_db.get(user["tenant_id"])}

@app.post("/api/v1/scan")
async def api_scan(req: ScanReq, tenant: dict = Depends(get_tenant_from_key)):
    result = scan_prompt(req.prompt)
    scan_id = secrets.token_hex(8)
    scans_db.append({"id": scan_id, "tenant_id": tenant["id"], "timestamp": datetime.now(timezone.utc).isoformat(), "allowed": result["allowed"], "risk_score": result["risk_score"]})
    tenant["scans"] += 1
    return {"scan_id": scan_id, **result}

@app.get("/api/dashboard/stats")
async def stats(user: dict = Depends(get_current_user)):
    tenant = tenants_db.get(user["tenant_id"])
    tenant_scans = [s for s in scans_db if s["tenant_id"] == tenant["id"]]
    blocked = len([s for s in tenant_scans if not s["allowed"]])
    return {"total_scans": len(tenant_scans), "blocked_scans": blocked, "api_key": tenant["api_key"], "plan": tenant["plan"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
