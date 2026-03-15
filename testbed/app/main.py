import asyncio
import jwt
import sqlite3
import os
import json
from fastapi import FastAPI, Request, Form, Depends, HTTPException, File, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Hexstrike V3.5 Benchmark App")

# --- Dummy DB Setup ---
conn = sqlite3.connect(':memory:', check_same_thread=False)
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, balance REAL, role TEXT)")
conn.execute("INSERT INTO users VALUES (1, 'admin', 10000.0, 'admin')")
conn.execute("INSERT INTO users VALUES (2, 'victim', 500.0, 'user')")
conn.execute("INSERT INTO users VALUES (3, 'attacker', 10.0, 'user')")
conn.commit()

# ==============================================================================
# 🔴 [VULNERABILITY 1] Logical Race Condition (FinTech Flow) 🔴
# ==============================================================================
class TransferRequest(BaseModel):
    from_id: int
    to_id: int
    amount: float

@app.post("/transfer")
async def transfer_funds(req: TransferRequest):
    """
    VULNERABILITY: Race condition in financial transaction.
    Balance is checked, then an I/O await happens, then balance is deducted.
    If multiple requests come in concurrently, they all pass the balance check.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM users WHERE id = ?", (req.from_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(404, "User not found")
        
    balance = row[0]
    
    if balance < req.amount:
        raise HTTPException(400, "Insufficient funds")
        
    # [RACE CONDITION WINDOW] - An external API call, logging, or delay
    await asyncio.sleep(0.1) 
    
    # Unsafe deduction without row locking or conditional updates
    new_balance = balance - req.amount
    cursor.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, req.from_id))
    
    # Add to recipient
    cursor.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (req.amount, req.to_id))
    conn.commit()
    
    return {"message": "Transfer successful", "new_balance": new_balance}


# ==============================================================================
# 🔴 [VULNERABILITY 2 & 3] Identity & JWT Chaos (Key Confusion + Multipart IDOR) 🔴
# ==============================================================================
PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"

@app.get("/validate_token")
async def validate_token(token: str):
    """
    VULNERABILITY: Key Confusion Attack + Algorithms bypass.
    Accepts 'none' algorithm. Uses PUBLIC_KEY as a symmetric secret if HS256 is passed.
    """
    try:
        # VULN: Validates HS256 using the Public Key as a string secret
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["HS256", "RS256", "none"])
        return payload
    except Exception as e:
        raise HTTPException(401, str(e))

@app.post("/upload_profile")
async def upload_profile_picture(
    metadata: str = Form(...), 
    file: UploadFile = File(...)
):
    """
    VULNERABILITY: Massive IDOR disguised inside multipart/form-data.
    The ID of the user being modified is extracted from a nested JSON string in the form data,
    bypassing traditional URL-based IDOR checks.
    """
    try:
        # Expected metadata: {"user": {"user_id": 2, "theme": "dark"}}
        data = json.loads(metadata)
        target_user = data.get("user", {}).get("user_id")
        
        if not target_user:
            raise HTTPException(400, "Missing user_id in metadata")
            
        # VULN: Updates profile for `target_user` without validating if the current session owns it
        content = await file.read()
        return {"status": "success", "updated_user": target_user, "file_size": len(content)}
    except Exception as e:
        raise HTTPException(400, str(e))


# ==============================================================================
# 🔴 [VULNERABILITY 4] Complex Supply Chain Attack (Through internal_lib) 🔴
# ==============================================================================
from .internal_lib import utils

@app.post("/process_data")
async def process_data(req: Request):
    """
    VULNERABILITY: Deeply nested insecure deserialization.
    Passes raw bytes down through multiple abstraction layers in internal_lib.
    """
    body = await req.body()
    # VULN: Passes untrusted payload.
    result = utils.safe_data_processor(body)
    return {"result": result}


# ==============================================================================
# 🔴 [VULNERABILITY 5] Architectural "Why" Trap (Bypass Middleware) 🔴
# ==============================================================================

@app.middleware("http")
async def global_auth_middleware(request: Request, call_next):
    # Dummy global auth block - normally you'd check a header
    if request.url.path.startswith("/api/") and request.headers.get("X-Token") != "secret":
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return await call_next(request)

@app.get("/internal/debug")
async def internal_debug_dashboard():
    """
    VULNERABILITY: Architectural bypass.
    This routes connects to the production DB structure but isn't prefixed with /api/.
    Therefore, the `global_auth_middleware` ignores it, creating a backdoor to sensitive data.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return {"debug_users": cursor.fetchall()}

