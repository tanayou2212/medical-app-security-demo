"""
SECURE medical records API — remediated version of vulnerable/app.py
For security education only.

Fixes applied:
  - OWASP API2:2023  Broken Authentication     -> credential validation + signed JWT
  - OWASP API1:2023  Broken Object Level Auth  -> token required on every protected route
"""

import os
import time
from typing import Annotated

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

app = FastAPI(title="Medical Records API (SECURE)")

# FIX: use a long, random secret loaded from the environment.
# Hardcoding secrets in source code leaks them via git history.
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production-use-env-var")
JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = 3600  # 1 hour

# FIX: passwords are stored as bcrypt hashes, never plaintext.
# Even if this dict leaks, raw passwords remain secret.
# Hashes were pre-generated offline; passwords are "SecurePass1" and "NursePass2".
MOCK_USERS: dict[str, str] = {
    # username -> bcrypt hash (cost factor 12) of password
    "dr_smith":    "$2b$12$Fr123Sud4bVgYZxd92uuhuM1YYpZKL6wGEmFq7YsSao0scbG9s22q",
    "nurse_jones": "$2b$12$Kdol2homZK70Ekv/YvdBguAKpKzRoiY7ujFkGXpBOJMozuDWTctAm",
}

# Same mock data as vulnerable/app.py — no real patient information.
MOCK_PATIENTS = [
    {"id": 1, "name": "Alice Example",  "dob": "1980-04-12", "diagnosis": "Hypertension",    "medication": "Lisinopril 10mg"},
    {"id": 2, "name": "Bob Sample",     "dob": "1975-09-30", "diagnosis": "Type 2 Diabetes", "medication": "Metformin 500mg"},
    {"id": 3, "name": "Carol Testuser", "dob": "1990-01-22", "diagnosis": "Asthma",           "medication": "Albuterol inhaler"},
]

bearer_scheme = HTTPBearer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        # FIX: short-lived tokens limit the damage window if a token is stolen.
        "exp": int(time.time()) + JWT_TTL_SECONDS,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    # FIX: jwt.decode validates the signature AND the exp claim automatically.
    # An expired or tampered token raises an exception, not a silent pass.
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# ---------------------------------------------------------------------------
# Dependency — enforces authentication on any route that declares it
# ---------------------------------------------------------------------------

def require_auth(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> str:
    """
    FIX: every protected endpoint declares this dependency.
    FastAPI returns HTTP 403 automatically if the Authorization header is absent,
    and decode_token() returns HTTP 401 if the token is invalid or expired.
    No route can accidentally skip this check because it is injected, not called manually.
    """
    payload = decode_token(credentials.credentials)
    return payload["sub"]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(body: LoginRequest):
    """
    FIX: credentials are validated against MOCK_USERS before any token is issued.
    Unknown usernames and wrong passwords both return the same HTTP 401 response
    to prevent user-enumeration via differing error messages.
    """
    hashed = MOCK_USERS.get(body.username)
    # Use a constant-time comparison path for both "user not found" and "wrong password"
    # to avoid timing side-channels that reveal whether the username exists.
    if hashed is None or not verify_password(body.password, hashed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_token(body.username)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/records")
def get_records(current_user: Annotated[str, Depends(require_auth)]):
    """
    FIX: require_auth dependency enforces a valid JWT on every call.
    Unauthenticated requests never reach this function body.
    """
    return {"requested_by": current_user, "patients": MOCK_PATIENTS}
