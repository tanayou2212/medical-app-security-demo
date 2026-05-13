# Medical App Security Demo

A hands-on security demonstration that shows how common API vulnerabilities appear in a medical records application and how to fix them. Each vulnerability is illustrated with a working exploit script and a paired secure implementation.

---

## 1. Project Overview

This demo simulates medical records REST APIs built with Python and FastAPI, covering both Web API and Mobile API attack surfaces. It deliberately implements five critical API security flaws across two versions, provides attack scripts that exploit each flaw, and shows remediated implementations that close every hole. The goal is to make abstract OWASP concepts concrete and observable.

| Version | API type | Vulnerabilities |
|---------|----------|-----------------|
| v1.0 | Web API | OWASP API1:2023, API2:2023 |
| v2.0 | Mobile API | OWASP API2:2023, API3:2023, API9:2023 |

---

## 2. Vulnerabilities Covered

### v1.0 Web API

#### OWASP API1:2023 - Broken Object Level Authorization (BOLA)

`GET /records` in the vulnerable app returns all patient records to any caller with no authentication check. An attacker can retrieve sensitive health data without presenting any credentials.

**Fix (secure/app.py):** Every request must carry a valid signed JWT. FastAPI's dependency injection system enforces this at the framework level - the route handler never executes if the token is absent or invalid.

#### OWASP API2:2023 - Broken Authentication

`POST /login` in the vulnerable app accepts any username and password combination and issues a token. The token is a predictable, hardcoded string that never expires.

**Fix (secure/app.py):** Credentials are validated against a predefined user list using bcrypt. Tokens are short-lived JWTs signed with HS256. Both "user not found" and "wrong password" return the same error message to prevent user enumeration.

### v2.0 Mobile API

#### OWASP API2:2023 - Broken Authentication (non-expiring JWT)

`POST /mobile/login` issues a JWT with no `exp` claim. A token captured once is valid forever, surviving password resets and account lockouts.

**Fix (secure/mobile_api.py):** JWT includes an `exp` claim set 30 minutes in the future. `jwt.decode()` enforces expiry automatically on every request.

#### OWASP API3:2023 - Broken Object Property Level Authorization

`GET /mobile/patient/{id}` returns the raw internal record including `password_hash`, `internal_id`, and `admin_flag` - fields that should never leave the backend.

**Fix (secure/mobile_api.py):** A `PatientResponse` Pydantic schema acts as an allowlist. FastAPI serialises every response through it, stripping any field not explicitly declared.

#### OWASP API9:2023 - Improper Inventory Management

`GET /mobile/debug/{id}` is an undocumented debug endpoint left in production. On error it returns a full Python stack trace and internal configuration including database credentials and the JWT secret.

**Fix (secure/mobile_api.py):** The debug endpoint is removed entirely. Exceptions are caught and logged server-side only; the client receives a generic HTTP 500 message.

---

## 3. Project Structure

```
medical-app-security-demo/
├── vulnerable/
│   ├── app.py            # v1.0 Web API  - vulnerable
│   └── mobile_api.py     # v2.0 Mobile API - vulnerable
├── attack/
│   ├── auth_bypass.py    # v1.0 exploit script
│   └── mobile_bypass.py  # v2.0 exploit script
├── secure/
│   ├── app.py            # v1.0 Web API  - remediated
│   └── mobile_api.py     # v2.0 Mobile API - remediated
└── docs/
    └── vulnerability-guide.md
```

Every file in `vulnerable/` has a corresponding fix in `secure/`. The two directories are always kept in sync.

---

## 4. How to Run

### Installation

```bash
pip install fastapi uvicorn pyjwt bcrypt requests
```

### v1.0 Web API

```bash
# Terminal 1 - vulnerable server
uvicorn vulnerable.app:app --port 8000 --reload

# Terminal 2 - attack
python attack/auth_bypass.py

# Terminal 3 - secure server (to verify fixes)
JWT_SECRET=replace-with-a-long-random-string uvicorn secure.app:app --port 8001 --reload
```

Re-run `attack/auth_bypass.py` with the secure server on port 8001 to see `[BLOCKED]` at every step.

### v2.0 Mobile API

```bash
# Terminal 1 - vulnerable server
uvicorn vulnerable.mobile_api:app --port 8002 --reload

# Terminal 2 - attack
python attack/mobile_bypass.py

# Terminal 3 - secure server (to verify fixes)
JWT_SECRET=replace-with-a-long-random-string uvicorn secure.mobile_api:app --port 8003 --reload
```

Re-run `attack/mobile_bypass.py` against port 8003 to see `[BLOCKED]` at every step. Update `BASE_URL` in the script to switch targets.

---

## 5. Educational Purpose

**This repository is for security education only.**

- All patient data is fictional mock data. No real health information is included anywhere.
- The attack scripts must only be run against the local demo instances in this repository.
- Do not deploy the vulnerable applications on a network accessible by others.
- Do not adapt the attack scripts for use against systems you do not own and have not been authorized to test.

Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

---

## 6. References

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP API9:2023 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
