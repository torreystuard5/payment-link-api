# Payment Link API

A small FastAPI backend to create and manage payment links with optional Stripe Checkout integration and a simple HTML UI.

## Features

- JWT login at `/login` with demo user `demo` / `password`.[web:11]
- Protected CRUD API for payment links, scoped by owner so each user only sees their own links.[file:44]
- `PaymentLink` fields: `amount` (cents), `currency`, `description`, `status` (`pending` / `paid` / `cancelled`), `expires_at`, `customer_email`, `processor` (`internal` or `stripe`), `processor_reference`, `owner`.[file:44][web:6]
- Validation: amount > 0, currencies limited to `usd`, `eur`, `gbp`, optional expiration in minutes.[file:44][web:6]
- Expiration: expired links return HTTP 410 and can’t be paid or cancelled.[file:44][web:11]
- Background “email” logging on mark-paid, written to `email_logs.txt`.[file:44]
- Stripe Checkout (test mode): when `processor="stripe"` and `STRIPE_SECRET_KEY` is set, link creation calls Stripe Checkout and stores the Session id and URL.[file:44][web:2][web:6]
- Simple HTML UI at `/ui` to log in, create links, list links, open URLs, and mark as paid/cancelled, plus `/success` and `/cancel` for Stripe redirects.[file:44][web:11]
- Clean repo with no secrets committed.[file:44]

## Requirements

- Python 3.11+ (recommended).
- Virtualenv (optional but recommended).
- Stripe test account and secret key for Stripe flows.[file:44][web:6]

## Setup

```bash
git clone https://github.com/<your-username>/payment-link-api.git
cd payment-link-api
python -m venv venv
# Windows PowerShell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Environment variables
You can use a .env file or set these in your shell:

SECRET_KEY: JWT signing key (random hex string).

STRIPE_SECRET_KEY: Stripe secret key (e.g. sk_test_...) for Checkout.

DATABASE_URL (optional): SQLModel/SQLAlchemy URL, default is local SQLite file.[file:44][web:7][web:13]

Example .env:

text
SECRET_KEY=change_me_to_random_hex
STRIPE_SECRET_KEY=sk_test_1234567890
DATABASE_URL=sqlite+aiosqlite:///./payment-links.db
Running the app
bash
# Windows PowerShell
.\venv\Scripts\Activate.ps1
$env:STRIPE_SECRET_KEY = "sk_test_..."
python -m uvicorn app.main:app --reload
Then open:

App UI: http://127.0.0.1:8000/ui

Interactive docs: http://127.0.0.1:8000/docs
[web:11]

Using the UI
Go to /ui.

Log in with demo / password to obtain a JWT and store it in localStorage.[file:44]

Create a payment link:

Choose processor: internal or stripe.

Set amount (cents), currency (usd / eur / gbp), optional expiration, description, customer email.[file:44]

Open the generated URL:

Internal: a local payment page.

Stripe: redirects to Stripe Checkout.[file:44]

After payment, mark a link as paid/cancelled from the UI. Background job logs a fake email to email_logs.txt.[file:44]

Stripe test card numbers
When using Stripe in test mode, use these test card details in Checkout. They never charge real money.[web:32][web:34]

Basic successful payment (Visa):

Number: 4242 4242 4242 4242

Expiry: any future date (e.g. 12/34)

CVC: any 3 digits (e.g. 123)

ZIP: any 5 digits[web:32][web:36]

Example Mastercard:

Number: 5555 5555 5555 4444

Expiry: any future date

CVC: any 3 digits[web:36][web:38]

To simulate failures (optional), see Stripe’s testing docs for cards that produce declines and other error scenarios.[web:32][web:34]

Running tests
bash
pytest
Tests live under the tests/ directory and cover auth, payment-link creation, and basic Stripe flows (where possible with test keys).