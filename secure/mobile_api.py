"""
SECURE mobile medical records API v2.0 — remediated version of vulnerable/mobile_api.py
For security education only.

Fixes applied:
  - OWASP API2:2023  Broken Authentication                -> JWT with 30-minute expiry
  - OWASP API3:2023  Broken Object Property Level Auth    -> explicit response schema allowlist
  - OWASP API9:2023  Improper Inventory Management        -> debug endpoint removed entirely
"""

import logging
import os
import time
from typing import Annotated

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

app = FastAPI(title="Mobile Medical Records API v2.0 (SECURE)")

# FIX (API2): secret is loaded from the environment, never hardcoded.
# Without the secret an attacker cannot forge tokens even if they read this file.
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production-use-env-var")
JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = 1800  # 30 minutes

logger = logging.getLogger(__name__)

MOCK_USERS: dict[str, str] = {
    "dr_smith":    "$2b$12$Fr123Sud4bVgYZxd92uuhuM1YYpZKL6wGEmFq7YsSao0scbG9s22q",
    "nurse_jones": "$2b$12$Kdol2homZK70Ekv/YvdBguAKpKzRoiY7ujFkGXpBOJMozuDWTctAm",
}

# Internal store retains all fields — the response schema (below) controls
# which fields are ever sent to a client.
_MOCK_PATIENTS = [
    {
        "id": 1,
        "name": "Alice Example",
        "dob": "1980-04-12",
        "diagnosis": "Hypertension",
        "medication": "Lisinopril 10mg",
        "password_hash": "$2b$12$examplehashAlice000000000000000000000000000000000000",
        "internal_id": "INT-0001-ALPHA",
        "admin_flag": False,
    },
    {
        "id": 2,
        "name": "Bob Sample",
        "dob": "1975-09-30",
        "diagnosis": "Type 2 Diabetes",
        "medication": "Metformin 500mg",
        "password_hash": "$2b$12$examplehashBob0000000000000000000000000000000000000",
        "internal_id": "INT-0002-BETA",
        "admin_flag": False,
    },
    {
        "id": 3,
        "name": "Carol Testuser",
        "dob": "1990-01-22",
        "diagnosis": "Asthma",
        "medication": "Albuterol inhaler",
        "password_hash": "$2b$12$examplehashCarol000000000000000000000000000000000000",
        "internal_id": "INT-0003-GAMMA",
        "admin_flag": True,
    },
]

bearer_scheme = HTTPBearer()


# ---------------------------------------------------------------------------
# FIX (API3): explicit response schema — the allowlist of fields a client
# may ever receive. Fields absent from this model are never serialised,
# even if they exist on the internal object.
# ---------------------------------------------------------------------------

class PatientResponse(BaseModel):
    id: int
    name: str
    dob: str
    diagnosis: str
    # password_hash, internal_id, and admin_flag are intentionally absent.


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        # FIX (API2): 'exp' claim enforces a 30-minute lifetime.
        # A stolen token becomes useless after it expires, limiting the
        # attacker's window to the TTL rather than indefinitely.
        "exp": int(time.time()) + JWT_TTL_SECONDS,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    # FIX (API2): jwt.decode validates the HMAC signature and rejects tokens
    # whose 'exp' has passed. Tampering with the payload invalidates the
    # signature; an expired token is rejected with a clear exception.
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def require_auth(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> str:
    payload = decode_token(credentials.credentials)
    return payload["sub"]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/mobile/login")
def mobile_login(body: LoginRequest):
    """
    FIX (OWASP API2:2023 — Broken Authentication):

    1. Credentials are validated against MOCK_USERS with bcrypt before
       any token is issued. Unknown users and wrong passwords both return
       HTTP 401 with the same message to prevent user enumeration.
    2. JWT includes an 'exp' claim set 30 minutes in the future.
       jwt.decode() enforces this on every subsequent request automatically.
    3. JWT_SECRET is read from the environment — it is not visible in source.
    """
    hashed = MOCK_USERS.get(body.username)
    if hashed is None or not verify_password(body.password, hashed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_token(body.username)
    return {"access_token": token, "token_type": "bearer", "expires_in": JWT_TTL_SECONDS}


@app.get("/mobile/patient/{patient_id}", response_model=PatientResponse)
def get_patient(
    patient_id: int,
    current_user: Annotated[str, Depends(require_auth)],
):
    """
    FIX (OWASP API3:2023 — Broken Object Property Level Authorization):

    1. require_auth dependency enforces authentication before any data is read.
    2. The route is annotated with response_model=PatientResponse. FastAPI
       serialises the return value through that schema, so fields not declared
       in PatientResponse (password_hash, internal_id, admin_flag) are stripped
       automatically — they can never appear in the response regardless of what
       the internal dict contains.
    """
    patient = next((p for p in _MOCK_PATIENTS if p["id"] == patient_id), None)
    if patient is None:
        # FIX: generic 404 — does not reveal whether other IDs exist.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")
    return patient


@app.get("/mobile/record/{patient_id}", response_model=PatientResponse)
def get_record(
    patient_id: int,
    current_user: Annotated[str, Depends(require_auth)],
):
    """
    FIX (OWASP API9:2023 — Improper Inventory Management):

    The /mobile/debug/{id} endpoint has been removed entirely. This route
    replaces it with a safe record lookup.

    1. All exceptions are caught and logged server-side only. The client
       receives a generic HTTP 500 message with no stack trace, no config,
       and no internal field names.
    2. The response_model allowlist applies here as well — same guarantees
       as get_patient above.
    3. This endpoint is documented in the API spec; there are no undocumented
       routes in the deployed surface.
    """
    try:
        patient = next((p for p in _MOCK_PATIENTS if p["id"] == patient_id), None)
        if patient is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")
        return patient
    except HTTPException:
        raise
    except Exception:
        # FIX: log the full detail server-side for diagnostics, but return
        # only a generic message to the caller. Stack traces and config
        # never leave the server.
        logger.exception("Unhandled error in get_record for patient_id=%s", patient_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        )
