# Payment Link API (FastAPI)

A small FastAPI project for creating and managing payment links with JWT auth and optional Stripe Checkout integration.[web:135][web:2]

## Features

- JWT-based login with a demo user (`demo` / `password`).[web:142]
- Create payment links with amount, currency, optional expiry, and customer email.
- Mark links as **paid** or **cancelled**.
- List payment links for the authenticated user.
- Optional Stripe Checkout session creation when `processor="stripe"`. [web:135][web:2]
- Environment-based configuration via `.env`.
- Basic test suite using `pytest` and `TestClient`.[web:138]

---

## Requirements

- Python 3.11+ (you are using 3.14).
- pip.
- (Optional) Stripe account + secret key if you want live Stripe sessions.[web:135][web:2]

---

## Getting started

### 1. Clone and create virtualenv

```bash
git clone <your-repo-url> payment-link-api
cd payment-link-api

python -m venv venv
# PowerShell
.\venv\Scripts\Activate.ps1
# or CMD
venv\Scripts\activate.bat
