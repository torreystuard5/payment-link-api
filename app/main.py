from enum import Enum
from datetime import datetime, timedelta
from typing import List, Optional
import os

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, EmailStr
from sqlmodel import SQLModel, Field as SQLField, Session, create_engine, select
from uuid import uuid4
import jwt
import stripe

# ---- Config ----

JWT_SECRET = "super-secret-change-me"
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = 60

ALLOWED_CURRENCIES = {"usd", "eur", "gbp"}

# Stripe secret key is loaded from environment, NOT hardcoded
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="Payment Link API", version="3.1.1")

sqlite_file_name = "payment_links.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(sqlite_url, echo=False, connect_args={"check_same_thread": False})

http_bearer = HTTPBearer(auto_error=True)


# ---- Auth helpers ----

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginBody(BaseModel):
    username: str
    password: str


def create_token(sub: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": sub,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRES_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---- Models ----

class PaymentStatus(str, Enum):
    pending = "pending"
    paid = "paid"
    cancelled = "cancelled"


class PaymentProcessor(str, Enum):
    internal = "internal"
    stripe = "stripe"


class PaymentLink(SQLModel, table=True):
    id: str = SQLField(primary_key=True, index=True)
    url: str
    amount: int
    currency: str
    description: Optional[str] = None
    status: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    customer_email: Optional[str] = None
    processor: str = "internal"
    processor_reference: Optional[str] = None
    owner: str = SQLField(index=True)


class PaymentLinkCreate(BaseModel):
    amount: int = Field(..., gt=0, description="Amount in cents")
    currency: str = Field("usd", description="Three-letter currency code")
    description: Optional[str] = None
    expires_in_minutes: Optional[int] = Field(
        default=60,
        ge=1,
        le=60 * 24 * 30,
        description="How long before the link expires (1 minute to 30 days)",
    )
    customer_email: Optional[EmailStr] = Field(
        default=None,
        description="Where to send a receipt when paid",
    )
    processor: PaymentProcessor = Field(
        default=PaymentProcessor.internal,
        description="Payment processor to use",
    )


class PaymentLinkRead(BaseModel):
    id: str
    url: str
    amount: int
    currency: str
    description: Optional[str]
    status: str
    created_at: datetime
    expires_at: Optional[datetime]
    customer_email: Optional[str]
    processor: str
    processor_reference: Optional[str]
    owner: str
    formatted_amount: str
    is_expired: bool


# ---- DB helpers ----

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


def ensure_not_expired(link: PaymentLink):
    if link.expires_at and datetime.utcnow() > link.expires_at:
        raise HTTPException(status_code=410, detail="Payment link has expired")


def to_read_model(link: PaymentLink) -> PaymentLinkRead:
    is_expired = bool(link.expires_at and datetime.utcnow() > link.expires_at)
    formatted_amount = f"{link.amount / 100:.2f} {link.currency.upper()}"
    return PaymentLinkRead(
        id=link.id,
        url=link.url,
        amount=link.amount,
        currency=link.currency,
        description=link.description,
        status=link.status,
        created_at=link.created_at,
        expires_at=link.expires_at,
        customer_email=link.customer_email,
        processor=link.processor,
        processor_reference=link.processor_reference,
        owner=link.owner,
        formatted_amount=formatted_amount,
        is_expired=is_expired,
    )


# ---- Background "email" helper ----

def log_email(to: str, subject: str, body: str):
    timestamp = datetime.utcnow().isoformat()
    line = f"{timestamp} | TO: {to} | SUBJECT: {subject} | BODY: {body}\n"
    with open("email_logs.txt", "a", encoding="utf-8") as f:
        f.write(line)


# ---- Public routes ----

@app.get("/")
def health_check():
    return {"status": "ok"}


@app.post("/login", response_model=TokenResponse)
def login(body: LoginBody):
    if body.username != "demo" or body.password != "password":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(sub=body.username)
    return TokenResponse(
        access_token=token,
        expires_in=JWT_EXPIRES_MINUTES * 60,
    )


@app.get("/success", response_class=HTMLResponse)
def success_page():
    return """
    <html>
      <head><title>Payment successful</title></head>
      <body style="font-family: sans-serif; max-width: 600px; margin: 40px auto; text-align: center;">
        <h1>Payment successful 🎉</h1>
        <p>Thank you. Your payment has been processed.</p>
        <p><a href="/ui">Back to dashboard</a></p>
      </body>
    </html>
    """


@app.get("/cancel", response_class=HTMLResponse)
def cancel_page():
    return """
    <html>
      <head><title>Payment cancelled</title></head>
      <body style="font-family: sans-serif; max-width: 600px; margin: 40px auto; text-align: center;">
        <h1>Payment cancelled</h1>
        <p>You didn’t complete the payment.</p>
        <p><a href="/ui">Back to dashboard</a></p>
      </body>
    </html>
    """


# ---- Protected API routes ----

@app.post(
    "/payment-links",
    response_model=PaymentLinkRead,
    status_code=status.HTTP_201_CREATED,
)
def create_payment_link(
    body: PaymentLinkCreate,
    session: Session = Depends(get_session),
    user: str = Depends(get_current_user),
):
    currency = body.currency.lower()
    if currency not in ALLOWED_CURRENCIES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported currency '{currency}'. Allowed: {sorted(ALLOWED_CURRENCIES)}",
        )

    now = datetime.utcnow()
    expires_at = None
    if body.expires_in_minutes:
        expires_at = now + timedelta(minutes=body.expires_in_minutes)

    link_id = str(uuid4())

    # Default internal behavior
    url = f"https://pay.example.com/{link_id}"
    processor_reference: Optional[str] = None

    if body.processor == PaymentProcessor.stripe:
        if not STRIPE_SECRET_KEY:
            raise HTTPException(status_code=500, detail="Stripe key not configured")
        try:
            session_obj = stripe.checkout.Session.create(
                mode="payment",
                line_items=[{
                    "price_data": {
                        "currency": currency,
                        "product_data": {"name": body.description or "Payment"},
                        "unit_amount": body.amount,
                    },
                    "quantity": 1,
                }],
                success_url="http://127.0.0.1:8000/success",
                cancel_url="http://127.0.0.1:8000/cancel",
            )
            url = session_obj.url
            processor_reference = session_obj.id
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Stripe error: {e}")

    db_link = PaymentLink(
        id=link_id,
        url=url,
        amount=body.amount,
        currency=currency,
        description=body.description,
        status=PaymentStatus.pending.value,
        created_at=now,
        expires_at=expires_at,
        customer_email=body.customer_email,
        processor=body.processor.value,
        processor_reference=processor_reference,
        owner=user,
    )
    session.add(db_link)
    session.commit()
    session.refresh(db_link)
    return to_read_model(db_link)


@app.get("/payment-links", response_model=List[PaymentLinkRead])
def list_payment_links(
    session: Session = Depends(get_session),
    user: str = Depends(get_current_user),
):
    statement = select(PaymentLink).where(PaymentLink.owner == user)
    results = session.exec(statement).all()
    return [to_read_model(link) for link in results]


@app.get("/payment-links/{link_id}", response_model=PaymentLinkRead)
def get_payment_link(
    link_id: str,
    session: Session = Depends(get_session),
    user: str = Depends(get_current_user),
):
    db_link = session.get(PaymentLink, link_id)
    if not db_link or db_link.owner != user:
        raise HTTPException(status_code=404, detail="Payment link not found")
    ensure_not_expired(db_link)
    return to_read_model(db_link)


@app.post("/payment-links/{link_id}/mark-paid", response_model=PaymentLinkRead)
def mark_payment_link_paid(
    link_id: str,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    user: str = Depends(get_current_user),
):
    db_link = session.get(PaymentLink, link_id)
    if not db_link or db_link.owner != user:
        raise HTTPException(status_code=404, detail="Payment link not found")
    ensure_not_expired(db_link)

    db_link.status = PaymentStatus.paid.value
    session.add(db_link)
    session.commit()
    session.refresh(db_link)

    if db_link.customer_email:
        subject = f"Payment received for {db_link.description or 'order'}"
        body = f"Thank you! We received {db_link.amount} {db_link.currency}."
        background_tasks.add_task(
            log_email,
            to=db_link.customer_email,
            subject=subject,
            body=body,
        )

    return to_read_model(db_link)


@app.post("/payment-links/{link_id}/mark-cancelled", response_model=PaymentLinkRead)
def mark_payment_link_cancelled(
    link_id: str,
    session: Session = Depends(get_session),
    user: str = Depends(get_current_user),
):
    db_link = session.get(PaymentLink, link_id)
    if not db_link or db_link.owner != user:
        raise HTTPException(status_code=404, detail="Payment link not found")
    ensure_not_expired(db_link)
    db_link.status = PaymentStatus.cancelled.value
    session.add(db_link)
    session.commit()
    session.refresh(db_link)
    return to_read_model(db_link)


@app.delete("/payment-links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_payment_link(
    link_id: str,
    session: Session = Depends(get_session),
    user: str = Depends(get_current_user),
):
    db_link = session.get(PaymentLink, link_id)
    if not db_link or db_link.owner != user:
        raise HTTPException(status_code=404, detail="Payment link not found")
    session.delete(db_link)
    session.commit()
    return


# ---- Simple HTML UI ----

@app.get("/ui", response_class=HTMLResponse)
def ui_page():
    return """
    <html>
      <head>
        <title>Payment Link UI</title>
        <style>
          body { font-family: sans-serif; max-width: 800px; margin: 20px auto; }
          input, button { margin: 4px 0; padding: 6px; }
          pre { background: #111; color: #0f0; padding: 10px; max-height: 200px; overflow: auto; }
          .card { border: 1px solid #ccc; padding: 10px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <h1>Payment Link Dashboard</h1>

        <h2>1. Login</h2>
        <p>Use the demo user to try things out.</p>
        <form id="login-form">
          <input name="username" value="demo" />
          <input name="password" type="password" value="password" />
          <button type="submit">Login</button>
        </form>
        <div>Token: <code id="token-display"></code></div>

        <hr />

        <h2>2. Create Payment Link</h2>
        <form id="create-form">
          <label>
            Amount (cents)<br />
            <input name="amount" type="number" value="5000" />
          </label><br />
          <label>
            Currency<br />
            <input name="currency" value="usd" />
          </label><br />
          <label>
            Description<br />
            <input name="description" value="Hoodie" />
          </label><br />
          <label>
            Customer email<br />
            <input name="customer_email" value="you@example.com" />
          </label><br />
          <label>
            Expires in minutes<br />
            <input name="expires_in_minutes" type="number" value="10" />
          </label><br />
          <label>
            Processor<br />
            <select name="processor">
              <option value="internal">internal (fake)</option>
              <option value="stripe">stripe (test mode)</option>
            </select>
          </label><br />
          <button type="submit">Create link</button>
        </form>

        <hr />

        <h2>3. Your Links</h2>
        <button id="refresh-links">Refresh links</button>
        <div id="links"></div>

        <hr />

        <h2>Debug log</h2>
        <pre id="debug"></pre>

        <script>
          const debug = (msg) => {
            const el = document.getElementById("debug");
            el.textContent = `[${new Date().toLocaleTimeString()}] ${msg}\\n` + el.textContent;
          };

          const apiBase = "http://127.0.0.1:8000";

          let token = localStorage.getItem("token") || "";
          document.getElementById("token-display").textContent = token ? token.slice(0, 20) + "..." : "";

          document.getElementById("login-form").onsubmit = async (e) => {
            e.preventDefault();
            const form = new FormData(e.target);
            const body = {
              username: form.get("username"),
              password: form.get("password"),
            };
            try {
              const res = await fetch(apiBase + "/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
              });
              const data = await res.json();
              if (!res.ok) {
                debug("Login failed: " + JSON.stringify(data));
                return;
              }
              token = data.access_token;
              localStorage.setItem("token", token);
              document.getElementById("token-display").textContent = token.slice(0, 20) + "...";
              debug("Logged in");
            } catch (err) {
              debug("Login error: " + err);
            }
          };

          document.getElementById("create-form").onsubmit = async (e) => {
            e.preventDefault();
            if (!token) {
              debug("No token. Login first.");
              return;
            }
            const form = new FormData(e.target);
            const body = {
              amount: Number(form.get("amount")),
              currency: form.get("currency"),
              description: form.get("description"),
              customer_email: form.get("customer_email") || null,
              expires_in_minutes: Number(form.get("expires_in_minutes")),
              processor: form.get("processor"),
            };
            try {
              const res = await fetch(apiBase + "/payment-links", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "Authorization": "Bearer " + token,
                },
                body: JSON.stringify(body),
              });
              const data = await res.json();
              debug("Create response: " + JSON.stringify(data, null, 2));
              loadLinks();
            } catch (err) {
              debug("Create error: " + err);
            }
          };

          async function loadLinks() {
            if (!token) {
              debug("No token. Login first.");
              return;
            }
            try {
              const res = await fetch(apiBase + "/payment-links", {
                headers: {
                  "Authorization": "Bearer " + token,
                },
              });
              const data = await res.json();
              const container = document.getElementById("links");
              container.innerHTML = "";
              data.forEach((link) => {
                const div = document.createElement("div");
                div.className = "card";
                div.innerHTML = `
                  <div><b>ID:</b> ${link.id}</div>
                  <div><b>URL:</b> <a href="${link.url}" target="_blank">${link.url}</a></div>
                  <div><b>Amount:</b> ${link.formatted_amount}</div>
                  <div><b>Status:</b> ${link.status}</div>
                  <div><b>Expired?:</b> ${link.is_expired}</div>
                  <div><b>Processor:</b> ${link.processor} (${link.processor_reference || ""})</div>
                  <button data-action="paid" data-id="${link.id}">Mark Paid</button>
                  <button data-action="cancel" data-id="${link.id}">Cancel</button>
                `;
                container.appendChild(div);
              });

              container.onclick = async (e) => {
                const btn = e.target;
                const action = btn.getAttribute("data-action");
                const id = btn.getAttribute("data-id");
                if (!action || !id) return;

                let endpoint = "";
                if (action === "paid") {
                  endpoint = `/payment-links/${id}/mark-paid`;
                } else if (action === "cancel") {
                  endpoint = `/payment-links/${id}/mark-cancelled`;
                }
                try {
                  const res = await fetch(apiBase + endpoint, {
                    method: "POST",
                    headers: { "Authorization": "Bearer " + token },
                  });
                  const data = await res.json();
                  debug(action + " response: " + JSON.stringify(data));
                  loadLinks();
                } catch (err) {
                  debug(action + " error: " + err);
                }
              };
            } catch (err) {
              debug("Load links error: " + err);
            }
          }

          document.getElementById("refresh-links").onclick = loadLinks;
        </script>
      </body>
    </html>
    """
