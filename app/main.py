from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, List

import os

import jwt
import stripe
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel, EmailStr, Field
from sqlmodel import Field as SQLField, SQLModel, Session, create_engine, select

# Load environment variables from .env
load_dotenv()

# Environment configuration
SECRET_KEY = os.getenv("SECRET_KEY", "dev_insecure_change_me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./payment-links.db")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# Database setup
engine = create_engine(DATABASE_URL, echo=False)


class PaymentLink(SQLModel, table=True):
    id: Optional[int] = SQLField(default=None, primary_key=True)
    amount: int = SQLField(index=True)  # in cents
    currency: str = SQLField(index=True)
    description: Optional[str] = None
    status: str = SQLField(default="pending", index=True)  # pending/paid/cancelled
    expires_at: Optional[datetime] = None
    customer_email: Optional[str] = None
    processor: str = SQLField(default="internal")  # internal/stripe
    processor_reference: Optional[str] = None  # e.g. Stripe session id
    owner: str = SQLField(index=True)


def init_db():
    SQLModel.metadata.create_all(engine)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


password_hash = PasswordHash.recommended()
fake_users_db = {
    "demo": {
        "username": "demo",
        "full_name": "Demo User",
        "email": "demo@example.com",
        "hashed_password": password_hash.hash("password"),
        "disabled": False,
    }
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return password_hash.hash(password)


def get_user(db, username: str) -> Optional[UserInDB]:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None


def authenticate_user(fake_db, username: str, password: str) -> Optional[UserInDB]:
    user = get_user(fake_db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)]
) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[UserInDB, Depends(get_current_user)],
) -> UserInDB:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


class PaymentLinkCreate(BaseModel):
    amount: int = Field(gt=0)
    currency: str = Field(pattern="^(usd|eur|gbp)$")
    description: Optional[str] = None
    expires_in_minutes: Optional[int] = Field(default=None, gt=0)
    customer_email: Optional[EmailStr] = None
    processor: str = Field(pattern="^(internal|stripe)$")


class PaymentLinkRead(BaseModel):
    id: int
    amount: int
    currency: str
    description: Optional[str]
    status: str
    expires_at: Optional[datetime]
    customer_email: Optional[EmailStr]
    processor: str
    processor_reference: Optional[str]
    owner: str


@app.on_event("startup")
def on_startup():
    init_db()


@app.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me", response_model=User)
async def read_users_me(
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    return current_user


def is_expired(link: PaymentLink) -> bool:
    if link.expires_at is None:
        return False
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = link.expires_at.replace(tzinfo=None)
    return expires_at <= now


def log_email(to_email: str, subject: str, body: str):
    with open("email_logs.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now(timezone.utc).isoformat()
        f.write(f"[{timestamp}] To: {to_email} | Subject: {subject} | {body}\n")


@app.post("/payment-links", response_model=PaymentLinkRead, status_code=201)
async def create_payment_link(
    payload: PaymentLinkCreate,
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    expires_at = None
    if payload.expires_in_minutes:
        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(minutes=payload.expires_in_minutes)
        ).replace(tzinfo=None)

    link = PaymentLink(
        amount=payload.amount,
        currency=payload.currency,
        description=payload.description,
        status="pending",
        expires_at=expires_at,
        customer_email=payload.customer_email,
        processor=payload.processor,
        processor_reference=None,
        owner=current_user.username,
    )

    if payload.processor == "stripe":
        if not STRIPE_SECRET_KEY:
            raise HTTPException(status_code=500, detail="Stripe not configured")
        try:
            session = stripe.checkout.Session.create(
                mode="payment",
                line_items=[
                    {
                        "price_data": {
                            "currency": payload.currency,
                            "product_data": {
                                "name": payload.description or "Payment"
                            },
                            "unit_amount": payload.amount,
                        },
                        "quantity": 1,
                    }
                ],
                success_url="http://127.0.0.1:8000/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url="http://127.0.0.1:8000/cancel",
            )
            link.processor_reference = session.id
        except Exception as e:
            print("Stripe error:", repr(e))
            raise HTTPException(status_code=502, detail=f"Stripe error: {e}")

    with Session(engine) as session_db:
        session_db.add(link)
        session_db.commit()
        session_db.refresh(link)
        return PaymentLinkRead(**link.dict())


@app.get("/payment-links", response_model=List[PaymentLinkRead])
async def list_payment_links(
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    with Session(engine) as session_db:
        stmt = select(PaymentLink).where(PaymentLink.owner == current_user.username)
        links = session_db.exec(stmt).all()
        return [PaymentLinkRead(**l.dict()) for l in links]


@app.post("/payment-links/{link_id}/pay", response_model=PaymentLinkRead)
async def mark_link_paid(
    link_id: int,
    background_tasks: BackgroundTasks,
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    with Session(engine) as session_db:
        link = session_db.get(PaymentLink, link_id)
        if not link or link.owner != current_user.username:
            raise HTTPException(status_code=404, detail="Link not found")

        if is_expired(link):
            raise HTTPException(status_code=410, detail="Payment link expired")

        if link.status != "pending":
            raise HTTPException(status_code=400, detail="Link not pending")

        link.status = "paid"
        session_db.add(link)
        session_db.commit()
        session_db.refresh(link)

        if link.customer_email:
            background_tasks.add_task(
                log_email,
                to_email=link.customer_email,
                subject="Payment received",
                body=f"Payment link {link.id} has been marked as paid.",
            )

        return PaymentLinkRead(**link.dict())


@app.post("/payment-links/{link_id}/cancel", response_model=PaymentLinkRead)
async def cancel_link(
    link_id: int,
    current_user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    with Session(engine) as session_db:
        link = session_db.get(PaymentLink, link_id)
        if not link or link.owner != current_user.username:
            raise HTTPException(status_code=404, detail="Link not found")

        if is_expired(link):
            raise HTTPException(status_code=410, detail="Payment link expired")

        if link.status != "pending":
            raise HTTPException(status_code=400, detail="Link not pending")

        link.status = "cancelled"
        session_db.add(link)
        session_db.commit()
        session_db.refresh(link)
        return PaymentLinkRead(**link.dict())


@app.get("/success")
async def stripe_success():
    return {"message": "Payment successful. You can close this page."}


@app.get("/cancel")
async def stripe_cancel():
    return {"message": "Payment cancelled. You can close this page."}
