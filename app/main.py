import hashlib
import hmac
import os
import secrets
import smtplib
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from threading import Lock

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import DateTime, Integer, String, create_engine, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

APP_NAME = "Universal OTP Service"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./otp.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class OTPChallenge(Base):
    __tablename__ = "otp_challenges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


Base.metadata.create_all(engine)
app = FastAPI(title=APP_NAME, version="1.0.0", description="Email OTP delivery and verification API.")

# In-process guardrails are useful on a single instance. Use a shared rate limiter
# (for example Redis) before scaling to multiple instances.
_rate_lock = Lock()
_send_events: dict[str, list[float]] = {}
_verify_events: dict[str, list[float]] = {}
_last_sent: dict[str, float] = {}


class SendOTPRequest(BaseModel):
    email: EmailStr


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str = Field(pattern=r"^\d{6}$")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_api_key(authorization: str | None = Header(default=None)):
    expected = os.getenv("API_SECRET_KEY", "")
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="Service API key is not configured.")
    supplied = authorization.removeprefix("Bearer ").strip() if authorization else ""
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return True


def otp_digest(email: str, otp: str) -> str:
    secret = os.getenv("OTP_PEPPER", "")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="OTP security secret is not configured.")
    return hmac.new(secret.encode(), f"{email.lower()}:{otp}".encode(), hashlib.sha256).hexdigest()


def check_rate_limit(bucket: dict[str, list[float]], key: str, limit: int, window: int):
    now = time.time()
    with _rate_lock:
        events = [t for t in bucket.get(key, []) if now - t < window]
        if len(events) >= limit:
            raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")
        events.append(now)
        bucket[key] = events


def send_email(to_email: str, otp: str):
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "465"))
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_APP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", username)
    if not username or not password or not sender:
        raise HTTPException(status_code=503, detail="Email delivery is not configured.")
    message = EmailMessage()
    message["Subject"] = "Your verification code"
    message["From"] = sender
    message["To"] = to_email
    message.set_content(
        f"Your verification code is {otp}. It expires in 5 minutes. "
        "If you did not request this code, you can ignore this email."
    )
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
                smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.starttls()
                smtp.login(username, password)
                smtp.send_message(message)
    except (OSError, smtplib.SMTPException):
        raise HTTPException(status_code=502, detail="Email delivery failed. Please try again later.")


@app.get("/")
def root():
    return {"service": APP_NAME, "status": "online", "docs": "/docs"}


@app.get("/health")
def health():
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return {"status": "healthy", "database": "connected"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")


@app.post("/send-otp", dependencies=[Depends(require_api_key)])
def send_otp(payload: SendOTPRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    check_rate_limit(_send_events, email, limit=5, window=3600)
    now_ts = time.time()
    with _rate_lock:
        last = _last_sent.get(email, 0)
        if now_ts - last < 60:
            raise HTTPException(status_code=429, detail="Please wait 60 seconds before requesting another OTP.")
        _last_sent[email] = now_ts

    otp = f"{secrets.randbelow(1_000_000):06d}"
    now = datetime.now(timezone.utc)
    challenge = OTPChallenge(
        email=email,
        code_hash=otp_digest(email, otp),
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        attempts=0,
    )
    db.add(challenge)
    db.commit()
    try:
        send_email(email, otp)
    except Exception:
        db.delete(challenge)
        db.commit()
        with _rate_lock:
            _last_sent.pop(email, None)
        raise
    return {"success": True, "message": "OTP sent successfully.", "expires_in_seconds": 300}


@app.post("/verify-otp", dependencies=[Depends(require_api_key)])
def verify_otp(payload: VerifyOTPRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    check_rate_limit(_verify_events, email, limit=10, window=900)
    now = datetime.now(timezone.utc)
    challenge = db.scalar(
        select(OTPChallenge)
        .where(OTPChallenge.email == email, OTPChallenge.used_at.is_(None))
        .order_by(OTPChallenge.created_at.desc())
        .limit(1)
    )
    if challenge is None:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
    if challenge.expires_at.replace(tzinfo=timezone.utc) <= now or challenge.attempts >= 5:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
    if not hmac.compare_digest(challenge.code_hash, otp_digest(email, payload.otp)):
        challenge.attempts += 1
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
    challenge.used_at = now
    db.commit()
    return {"success": True, "verified": True}


@app.on_event("startup")
def cleanup_expired():
    # Expired challenges are ignored during verification; this keeps storage tidy.
    with SessionLocal() as db:
        db.execute(
            update(OTPChallenge)
            .where(OTPChallenge.expires_at < datetime.now(timezone.utc) - timedelta(days=1))
            .values(used_at=datetime.now(timezone.utc))
        )
        db.commit()
