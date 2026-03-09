"""
HEXSTRIKE SECURITY TESTBED — Deliberately Vulnerable FastAPI Application.

⚠ FOR TESTING PURPOSES ONLY. DO NOT DEPLOY TO PRODUCTION. ⚠

This application contains intentional vulnerabilities across ALL
methodology sections to serve as a benchmark for the Security Sentinel.

Vulnerabilities covered:
  [DISCOVERY]   — Hidden admin endpoints, exposed .env, debug mode
  [MODELING]    — Broken trust boundaries, insecure data flow
  [DEEP_SCAN]   — SQLi, XSS, IDOR, hardcoded secrets, broken BAC
  [VALIDATION]  — No rate limiting, no input sanitization, no CSP headers
"""

import os
import pickle
import sqlite3
import subprocess
from base64 import b64decode

from fastapi import FastAPI, Request, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse

# ═══════════════════════════════════════════════════════════════
# VULN: [DISCOVERY/SECRETS] Hardcoded credentials & API keys
# ═══════════════════════════════════════════════════════════════
DATABASE_URL = "sqlite:///./production.db"
SECRET_KEY = "super-secret-key-12345-do-not-share"
ADMIN_PASSWORD = "admin123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "jwt-secret-never-rotate-this"
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

app = FastAPI(
    title="Vulnerable Corp API",
    # VULN: [DISCOVERY/DEBUG] Debug mode enabled in production
    debug=True,
)


# ═══════════════════════════════════════════════════════════════
# Database setup — raw SQL, no ORM
# ═══════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect("production.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,  -- VULN: plaintext passwords
            email TEXT,
            role TEXT DEFAULT 'user',
            ssn TEXT,
            credit_card TEXT
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT
        );
        INSERT OR IGNORE INTO users (id, username, password, email, role, ssn, credit_card)
        VALUES
            (1, 'admin', 'admin123', 'admin@corp.com', 'admin', '123-45-6789', '4111111111111111'),
            (2, 'user1', 'password', 'user1@corp.com', 'user', '987-65-4321', '4222222222222222'),
            (3, 'manager', 'manager1', 'mgr@corp.com', 'manager', '555-55-5555', '4333333333333333');
        INSERT OR IGNORE INTO posts (id, user_id, title, content)
        VALUES
            (1, 1, 'Admin Notes', 'Internal: AWS keys are in /etc/secrets'),
            (2, 2, 'Hello World', 'My first post');
    """)
    db.commit()
    db.close()


init_db()


# ═══════════════════════════════════════════════════════════════
# VULN: [DISCOVERY/HIDDEN_ENDPOINTS] Undocumented admin routes
# ═══════════════════════════════════════════════════════════════
@app.get("/admin/debug", include_in_schema=False)
async def admin_debug():
    """Hidden debug endpoint — leaks environment variables."""
    return {
        "env": dict(os.environ),
        "db": DATABASE_URL,
        "secret": SECRET_KEY,
        "aws_key": AWS_ACCESS_KEY,
    }


@app.get("/admin/shell", include_in_schema=False)
async def admin_shell(cmd: str = "whoami"):
    """VULN: [DEEP_SCAN/RCE] Remote Code Execution via os command."""
    # VULN: Direct shell command injection
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"stdout": result.stdout, "stderr": result.stderr}


@app.get("/.env")
async def exposed_env():
    """VULN: [DISCOVERY/EXPOSED_CONFIG] .env file served directly."""
    return Response(
        content=f"SECRET_KEY={SECRET_KEY}\nAWS_KEY={AWS_ACCESS_KEY}\nSTRIPE={STRIPE_KEY}\n",
        media_type="text/plain",
    )


@app.get("/.git/config")
async def exposed_git():
    """VULN: [DISCOVERY/EXPOSED_GIT] Git config exposed."""
    return Response(
        content="[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://token:ghp_LEAK@github.com/corp/internal.git\n",
        media_type="text/plain",
    )


# ═══════════════════════════════════════════════════════════════
# VULN: [DEEP_SCAN/SQLI] SQL Injection
# ═══════════════════════════════════════════════════════════════
@app.get("/api/users/search")
async def search_users(q: str = ""):
    """VULN: Raw string interpolation in SQL query."""
    db = get_db()
    # VULN: SQL Injection — no parameterized query
    query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{q}%'"
    try:
        results = db.execute(query).fetchall()
        return [dict(r) for r in results]
    except Exception as e:
        return {"error": str(e)}  # VULN: Stack trace leak


@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    """VULN: [DEEP_SCAN/IDOR] Insecure Direct Object Reference — no auth check."""
    db = get_db()
    # VULN: Returns ALL fields including SSN, credit card, password
    user = db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
    if user:
        return dict(user)  # VULN: Leaks PII — ssn, credit_card, password
    return {"error": "Not found"}


# ═══════════════════════════════════════════════════════════════
# VULN: [DEEP_SCAN/BAC] Broken Access Control
# ═══════════════════════════════════════════════════════════════
@app.post("/api/users/{user_id}/role")
async def change_role(user_id: int, role: str = "admin"):
    """VULN: Any user can escalate privileges — no authorization check."""
    db = get_db()
    db.execute(f"UPDATE users SET role = '{role}' WHERE id = {user_id}")
    db.commit()
    return {"message": f"Role updated to {role}"}  # VULN: Also SQLi


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int):
    """VULN: No authentication, no authorization — anyone can delete users."""
    db = get_db()
    db.execute(f"DELETE FROM users WHERE id = {user_id}")
    db.commit()
    return {"message": "User deleted"}


# ═══════════════════════════════════════════════════════════════
# VULN: [DEEP_SCAN/XSS] Cross-Site Scripting
# ═══════════════════════════════════════════════════════════════
@app.get("/profile", response_class=HTMLResponse)
async def user_profile(name: str = "Guest"):
    """VULN: Reflected XSS — user input rendered without escaping."""
    return f"""
    <html>
    <head><title>Profile - {name}</title></head>
    <body>
        <h1>Welcome, {name}!</h1>
        <p>Your profile page.</p>
        <script>console.log('Page loaded for {name}')</script>
    </body>
    </html>
    """


@app.get("/api/posts/{post_id}", response_class=HTMLResponse)
async def get_post(post_id: int):
    """VULN: Stored XSS — post content rendered as raw HTML."""
    db = get_db()
    post = db.execute(f"SELECT * FROM posts WHERE id = {post_id}").fetchone()
    if post:
        return f"<h2>{post['title']}</h2><div>{post['content']}</div>"  # VULN: No sanitization
    return "<p>Not found</p>"


# ═══════════════════════════════════════════════════════════════
# VULN: [DEEP_SCAN/DESERIALIZATION] Insecure Deserialization
# ═══════════════════════════════════════════════════════════════
@app.post("/api/import")
async def import_data(request: Request):
    """VULN: Deserializes untrusted pickle data — RCE vector."""
    body = await request.body()
    try:
        # VULN: pickle.loads on untrusted user input = RCE
        data = pickle.loads(b64decode(body))
        return {"imported": len(data) if isinstance(data, list) else 1}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════
# VULN: [MODELING/TRUST_BOUNDARY] Broken Trust Boundaries
# ═══════════════════════════════════════════════════════════════
@app.post("/api/webhook")
async def external_webhook(request: Request):
    """VULN: Accepts external webhooks without signature verification."""
    body = await request.json()
    # VULN: No HMAC verification, no origin check
    # VULN: Blindly trusts and processes external data
    if body.get("action") == "delete_all":
        db = get_db()
        db.execute("DELETE FROM posts")
        db.commit()
        return {"message": "All posts deleted by webhook"}
    return {"processed": True}


@app.get("/api/internal/metrics", include_in_schema=False)
async def internal_metrics():
    """VULN: Internal metrics endpoint exposed without auth."""
    db = get_db()
    users = db.execute("SELECT COUNT(*) as c FROM users").fetchone()
    return {
        "total_users": users["c"],
        "db_path": DATABASE_URL,
        "secret": SECRET_KEY,
        "memory": "256MB",
    }


# ═══════════════════════════════════════════════════════════════
# VULN: [DEEP_SCAN/SSRF] Server-Side Request Forgery
# ═══════════════════════════════════════════════════════════════
@app.get("/api/fetch")
async def fetch_url(url: str = "http://localhost"):
    """VULN: SSRF — fetches arbitrary URL from server context."""
    import urllib.request
    try:
        # VULN: No URL validation, can hit internal services / metadata
        response = urllib.request.urlopen(url, timeout=5)
        return {"status": response.status, "body": response.read(1024).decode()}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════
# VULN: [VALIDATION/MISSING] No security headers, no rate limiting
# ═══════════════════════════════════════════════════════════════
@app.middleware("http")
async def insecure_middleware(request: Request, call_next):
    response = await call_next(request)
    # VULN: Missing security headers
    # No Content-Security-Policy
    # No X-Frame-Options
    # No X-Content-Type-Options
    # No Strict-Transport-Security
    response.headers["Server"] = "VulnerableCorp/1.0"  # VULN: Server version leak
    response.headers["X-Powered-By"] = "FastAPI-Debug"
    return response


@app.get("/")
async def root():
    return {"app": "VulnerableCorp API", "version": "1.0.0-debug", "docs": "/docs"}
