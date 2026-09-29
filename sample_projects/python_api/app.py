import sqlite3
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

app = FastAPI(
    title="Sample Vulnerable Python API Target",
    description="Deliberately vulnerable test target for StressX autonomous security testing.",
    version="1.0.0"
)

# Seed in-memory SQLite database
def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE items (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL
        )
    """)
    cursor.execute("""
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            username TEXT,
            email TEXT,
            role TEXT,
            secret_data TEXT
        )
    """)
    cursor.executemany(
        "INSERT INTO items VALUES (?, ?, ?, ?)",
        [
            (1, "Database Backup", "Full automated SQL dump", 150.0),
            (2, "API Gateway", "Reverse proxy and rate limiter", 300.0),
            (3, "Security Scanner", "Static & dynamic auditing suite", 500.0)
        ]
    )
    cursor.executemany(
        "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
        [
            ("user_101", "alice", "alice@corp.local", "user", "Alice API Token: tok_live_alice_9821"),
            ("user_102", "bob", "bob@corp.local", "user", "Bob confidential salary details: $140,000"),
            ("admin_001", "root", "root@corp.local", "admin", "Master Key: vault_master_k3y_live")
        ]
    )
    conn.commit()
    return conn

DB = init_db()


class LoginPayload(BaseModel):
    username: str
    password: str


@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "sample-python-api",
        "endpoints": [
            "/health",
            "/api/users/{user_id}",
            "/api/debug/config",
            "/api/auth/login",
            "/api/search",
            "/api/admin/config"
        ]
    }


# 1. Health check endpoint
@app.get("/health")
def health():
    return {"status": "healthy"}


# 2. Information Disclosure: Unauthenticated debug configuration
@app.get("/api/debug/config")
def debug_config():
    """VULNERABILITY: Unauthenticated endpoint exposing secrets and credentials."""
    return {
        "ENVIRONMENT": "production",
        "DATABASE_URL": "postgresql://appuser:SecretVaultPass123!@10.0.1.20:5432/app_db",
        "JWT_SECRET": "live_signing_secret_key_88921",
        "AWS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "REDIS_PASSWORD": "redis_cluster_password_7781"
    }


# 3. Unsafe Input Handling: SQL Injection
@app.get("/api/search")
def search_items(q: str = Query(..., description="Search query")):
    """VULNERABILITY: Raw SQL string interpolation allows SQL injection."""
    cursor = DB.cursor()
    query = f"SELECT id, name, description, price FROM items WHERE name LIKE '%{q}%'"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        return {
            "query": q,
            "count": len(rows),
            "results": [{"id": r[0], "name": r[1], "description": r[2], "price": r[3]} for r in rows]
        }
    except sqlite3.OperationalError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Database syntax exception: {str(e)} | Query: {query}"
        )


# 4. Authentication Weakness: Default / hardcoded credentials
@app.post("/api/auth/login")
def login(payload: LoginPayload):
    """Authentication portal accepting standard test credentials."""
    if payload.username == "admin" and payload.password == "admin123":
        return {
            "token": "bearer_token_admin_root_001",
            "user_id": "admin_001",
            "role": "admin"
        }
    if payload.username == "alice" and payload.password == "password123":
        return {
            "token": "bearer_token_alice_101",
            "user_id": "user_101",
            "role": "user"
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")


# 5. Authorization Weakness: Insecure Direct Object Reference (IDOR)
@app.get("/api/users/{user_id}")
def get_user(user_id: str, authorization: Optional[str] = Header(None)):
    """VULNERABILITY: Broken object level authorization.
    
    Any authenticated user can view any other user's confidential records.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token authorization required")

    cursor = DB.cursor()
    cursor.execute("SELECT id, username, email, role, secret_data FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "role": row[3],
        "confidential_notes": row[4]
    }


# 6. Privilege Escalation: Header spoofing
@app.get("/api/admin/config")
def admin_config(x_original_role: Optional[str] = Header(None, alias="X-Original-Role")):
    """VULNERABILITY: Trusts client-supplied X-Original-Role header for admin authorization."""
    if x_original_role == "admin":
        return {
            "admin_access": "GRANTED",
            "system_flags": {
                "debug_mode": True,
                "allow_eval": True,
                "root_cluster_ip": "10.0.1.1"
            },
            "authorized_by": "Header-X-Original-Role"
        }
    raise HTTPException(status_code=403, detail="Forbidden: Administrative privileges required")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
