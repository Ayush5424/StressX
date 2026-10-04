from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Sample Compose Target Application", version="1.0.0")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "compose_web",
        "database": "postgresql://db:5432/appdb"
    }


@app.get("/api/items")
def list_items():
    return [
        {"id": 1, "name": "Item Alpha", "price": 19.99},
        {"id": 2, "name": "Item Beta", "price": 49.99}
    ]


@app.get("/api/users/{user_id}")
def get_user(user_id: str):
    if user_id in ("1", "101"):
        return {"id": user_id, "username": "alice", "role": "user"}
    elif user_id in ("2", "102"):
        return {"id": user_id, "username": "bob", "role": "user"}
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/api/auth/login")
def login(req: LoginRequest):
    if req.username == "admin" and req.password == "admin123":
        return {"token": "test-admin-token-12345", "role": "admin"}
    elif req.username == "alice" and req.password == "alice123":
        return {"token": "test-alice-token-54321", "role": "user"}
    raise HTTPException(status_code=401, detail="Invalid credentials")
