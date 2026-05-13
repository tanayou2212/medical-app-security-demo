"""
VULNERABLE medical records API — for security education only.
DO NOT deploy in production.

Vulnerabilities demonstrated:
  - OWASP API1:2023  Broken Object Level Authorization
  - OWASP API2:2023  Broken Authentication
"""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Medical Records API (VULNERABLE)")

# VULNERABILITY: sensitive data stored in plain memory with no access control.
# Any caller who reaches this process can read or modify it.
MOCK_PATIENTS = [
    {"id": 1, "name": "Alice Example",   "dob": "1980-04-12", "diagnosis": "Hypertension",    "medication": "Lisinopril 10mg"},
    {"id": 2, "name": "Bob Sample",      "dob": "1975-09-30", "diagnosis": "Type 2 Diabetes", "medication": "Metformin 500mg"},
    {"id": 3, "name": "Carol Testuser",  "dob": "1990-01-22", "diagnosis": "Asthma",           "medication": "Albuterol inhaler"},
]


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(body: LoginRequest):
    # VULNERABILITY: no credential validation whatsoever.
    # Any username + password combination succeeds and receives a token.
    # The token is a static, predictable string — not signed, not expiring.
    fake_token = f"token-{body.username}-hardcoded"
    return {"access_token": fake_token, "token_type": "bearer"}


@app.get("/records")
def get_records():
    # VULNERABILITY: no Authorization header is checked.
    # The endpoint returns all patient records to any unauthenticated request.
    # This violates HIPAA minimum-necessary and OWASP API1 (BOLA).
    return {"patients": MOCK_PATIENTS}
