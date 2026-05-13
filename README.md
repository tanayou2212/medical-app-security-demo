# Medical App Security Demo

A hands-on security demonstration that shows how common API vulnerabilities appear in a medical records application — and how to fix them. Each vulnerability is illustrated with a working exploit script and a paired secure implementation.

---

## 1. Project Overview

This demo simulates a minimal medical records REST API built with Python and FastAPI. It deliberately implements two critical API security flaws, provides an attack script that exploits them, and then shows a remediated version that closes each hole. The goal is to make abstract OWASP concepts concrete and observable.

---

## 2. Vulnerabilities Covered

### OWASP API1:2023 — Broken Object Level Authorization (BOLA)

`GET /records` in the vulnerable app returns all patient records to any caller, with no authentication check whatsoever. An attacker can retrieve sensitive health data without presenting any credentials.

**Fix (secure/app.py):** Every request must carry a valid signed JWT. FastAPI's dependency injection system enforces this at the framework level — the route handler never executes if the token is absent or invalid.

### OWASP API2:2023 — Broken Authentication

`POST /login` in the vulnerable app accepts any username and password combination and issues a token. The token is a predictable, hardcoded string that never expires.

**Fix (secure/app.py):** Credentials are validated against a predefined user list using bcrypt. Tokens are short-lived JWTs signed with HS256. Both "user not found" and "wrong password" return the same error message to prevent user enumeration.

---

## 3. Project Structure

```
medical-app-security-demo/
├── vulnerable/
│   └── app.py          # Intentionally vulnerable FastAPI app
├── attack/
│   └── auth_bypass.py  # PoC exploit script
├── secure/
│   └── app.py          # Remediated FastAPI app
└── docs/               # Threat models and analysis notes
```

`vulnerable/` and `secure/` are always kept in sync — every vulnerability in `vulnerable/` has a corresponding fix in `secure/`.

---

## 4. How to Run

### Installation

```bash
pip install fastapi uvicorn pyjwt "passlib[bcrypt]" requests
```

### Start the vulnerable server

```bash
uvicorn vulnerable.app:app --port 8000 --reload
```

### Run the attack script

In a second terminal, with the vulnerable server running:

```bash
python attack/auth_bypass.py
```

The script prints each step of the exploit and the patient data it exposes.

### Start the secure server

```bash
JWT_SECRET=replace-with-a-long-random-string \
  uvicorn secure.app:app --port 8001 --reload
```

Running the same attack script against port 8001 will return HTTP 401 at both steps.

---

## 5. Educational Purpose

**This repository is for security education only.**

- All patient data is fictional mock data. No real health information is included anywhere.
- The attack scripts must only be run against the local demo instances in this repository.
- Do not deploy the vulnerable application on a network accessible by others.
- Do not adapt the attack scripts for use against systems you do not own and have not been authorized to test.

Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

---

## 6. References

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
