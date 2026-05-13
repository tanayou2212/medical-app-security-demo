"""
VULNERABLE mobile medical records API v2.0 — for security education only.
DO NOT deploy in production.

Vulnerabilities demonstrated:
  - OWASP API2:2023  Broken Authentication         (POST /mobile/login)
  - OWASP API3:2023  Broken Object Property Level  (GET /mobile/patient/{id})
  - OWASP API9:2023  Improper Inventory Management  (GET /mobile/debug/{id})
"""

import traceback

import jwt
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Mobile Medical Records API v2.0 (VULNERABLE)")

# VULNERABILITY: secret is hardcoded in source code.
# Anyone with read access to this file can forge tokens.
JWT_SECRET = "mobile-secret-hardcoded"
JWT_ALGORITHM = "HS256"

# Internal patient store — includes sensitive server-side fields that should
# never leave the backend (password_hash, internal_id, admin_flag).
MOCK_PATIENTS = [
    {
        "id": 1,
        "name": "Alice Example",
        "dob": "1980-04-12",
        "diagnosis": "Hypertension",
        "medication": "Lisinopril 10mg",
        # Fields below are internal — they must never be returned to clients
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

# Internal system config — referenced in the debug endpoint to show what
# gets leaked when error handling is absent.
_INTERNAL_CONFIG = {
    "db_host": "db.internal.hospital.local",
    "db_port": 5432,
    "db_user": "app_user",
    "db_password": "hunter2",
    "jwt_secret": JWT_SECRET,
}


class LoginRequest(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Endpoint 1 — Broken Authentication (OWASP API2:2023)
# ---------------------------------------------------------------------------

@app.post("/mobile/login")
def mobile_login(body: LoginRequest):
    """
    VULNERABILITY (OWASP API2:2023 — Broken Authentication):

    1. No credential validation: any username/password is accepted.
    2. JWT has NO 'exp' (expiration) claim.
       A token issued today is valid indefinitely — even after the user
       is deleted, locked out, or their account is compromised.
    3. The hardcoded secret above means an attacker can mint their own
       tokens without calling this endpoint at all.
    """
    # VULNERABILITY: no lookup against a user store — any input succeeds.
    payload = {
        "sub": body.username,
        # 'exp' claim is intentionally omitted — token never expires.
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Endpoint 2 — Broken Object Property Level Authorization (OWASP API3:2023)
# ---------------------------------------------------------------------------

@app.get("/mobile/patient/{patient_id}")
def get_patient(patient_id: int):
    """
    VULNERABILITY (OWASP API3:2023 — Broken Object Property Level Authorization):

    The endpoint returns the raw internal dict for the patient, including:
      - password_hash  — bcrypt hash; useful for offline cracking
      - internal_id    — exposes internal system identifiers
      - admin_flag     — reveals privilege level; an attacker learns which
                         accounts to target for privilege escalation

    A secure implementation would serialise through an explicit response
    schema that allowlists only the fields the client is permitted to see.
    """
    # VULNERABILITY: no authentication check — any anonymous caller can
    # retrieve any patient record by guessing sequential integer IDs (BOLA).
    patient = next((p for p in MOCK_PATIENTS if p["id"] == patient_id), None)
    if patient is None:
        return {"error": "patient not found"}

    # VULNERABILITY: the full internal dict is returned without filtering.
    # password_hash, internal_id, and admin_flag are all exposed.
    return patient


# ---------------------------------------------------------------------------
# Endpoint 3 — Improper Inventory Management / Information Disclosure
#              (OWASP API9:2023)
# ---------------------------------------------------------------------------

@app.get("/mobile/debug/{patient_id}")
def debug_patient(patient_id: int):
    """
    VULNERABILITY (OWASP API9:2023 — Improper Inventory Management):

    This endpoint exists as a "debug helper" that was never removed before
    deployment. It is undocumented in the public API spec but is reachable
    by any client that probes the URL space.

    On error it returns:
      - Full Python stack trace — reveals file paths, library versions,
        and internal code structure useful for targeted exploits.
      - Internal configuration dict — exposes DB credentials and the JWT
        secret, allowing an attacker to forge tokens and access the database
        directly.

    Even without triggering an error, the endpoint's existence confirms
    internal implementation details (Python / FastAPI, internal field names).
    """
    try:
        # VULNERABILITY: deliberately triggers a KeyError to demonstrate
        # what gets leaked when exceptions are not caught and sanitised.
        patient = MOCK_PATIENTS[patient_id]  # int used as list index, not ID
        return {"debug_data": patient, "internal_config": _INTERNAL_CONFIG}
    except Exception:
        # VULNERABILITY: raw traceback and internal config are returned in
        # the response body instead of being written to a server-side log.
        return {
            "error": "debug lookup failed",
            "traceback": traceback.format_exc(),
            "internal_config": _INTERNAL_CONFIG,
        }
