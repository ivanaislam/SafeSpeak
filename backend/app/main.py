from __future__ import annotations

import os
import re
import secrets
import string
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

try:
    import spacy
except ImportError:  # pragma: no cover - optional dependency
    spacy = None


ROOT_DIR = Path(__file__).resolve().parents[2]
FRONTEND_INDEX = ROOT_DIR / "frontend" / "index.html"
FRONTEND_TRACK = ROOT_DIR / "frontend" / "track.html"
FRONTEND_STYLE = ROOT_DIR / "frontend" / "style.css"
BACKEND_DIR = ROOT_DIR / "backend"
UPLOAD_DIR = BACKEND_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
HOME_SHOWCASE_IMAGES: dict[str, Path] = {
    "anonymous-reporting": ROOT_DIR / "docs" / "images" / "anonymous-reporting.jpeg",
    "secure-case-tracking": ROOT_DIR / "docs" / "images" / "case-tracking.jpeg",
    "privacy-protection": ROOT_DIR / "docs" / "images" / "privacy-redaction.jpeg",
}


def sqlite_url(path: Path) -> str:
    normalized = str(path.resolve()).replace("\\", "/")
    return f"sqlite:///{normalized}"


def load_nlp_pipeline():
    global NLP_PIPELINE
    global NLP_PIPELINE_TRIED

    if NLP_PIPELINE_TRIED:
        return NLP_PIPELINE

    NLP_PIPELINE_TRIED = True
    if spacy is None:
        return None

    for model_name in (NLP_MODEL_NAME, "en_core_web_sm"):
        try:
            pipeline = spacy.load(model_name)
            pipeline.max_length = max(pipeline.max_length, NLP_MAX_LENGTH)
            NLP_PIPELINE = pipeline
            return NLP_PIPELINE
        except Exception:
            continue

    return None


DATABASE_URL = os.getenv("SAFESPEAK_DATABASE_URL", sqlite_url(BACKEND_DIR / "safespeak.db"))
SECRET_KEY = os.getenv("SAFESPEAK_SECRET_KEY", "dev-secret-key-change-me")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("SAFE_SPEAK_TOKEN_HOURS", "8"))
DEFAULT_ADMIN_USERNAME = os.getenv("SAFE_SPEAK_ADMIN_USERNAME", "admin@safespeak.local")
DEFAULT_ADMIN_PASSWORD = os.getenv("SAFE_SPEAK_ADMIN_PASSWORD", "SafeSpeak@123")
NLP_MODEL_NAME = os.getenv("SAFESPEAK_NLP_MODEL", "en_core_web_sm")
NLP_MAX_LENGTH = int(os.getenv("SAFESPEAK_NLP_MAX_LENGTH", "200000"))
ADMIN_SECURITY_EVENT_LIMIT = int(os.getenv("SAFESPEAK_ADMIN_SECURITY_EVENT_LIMIT", "200"))
ADMIN_AUDIT_LOG_LIMIT = int(os.getenv("SAFESPEAK_ADMIN_AUDIT_LOG_LIMIT", "200"))
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("SAFESPEAK_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",")
    if origin.strip()
]
ADMIN_LOGIN_MAX_ATTEMPTS = int(os.getenv("SAFESPEAK_ADMIN_LOGIN_MAX_ATTEMPTS", "5"))
ADMIN_LOGIN_WINDOW_MINUTES = int(os.getenv("SAFESPEAK_ADMIN_LOGIN_WINDOW_MINUTES", "15"))
ADMIN_LOGIN_LOCKOUT_MINUTES = int(os.getenv("SAFESPEAK_ADMIN_LOGIN_LOCKOUT_MINUTES", "15"))

NLP_ENTITY_REPLACEMENTS: dict[str, str] = {
    "PERSON": "[REDACTED_NAME]",
    "ORG": "[REDACTED_ORG]",
    "GPE": "[REDACTED_LOCATION]",
    "LOC": "[REDACTED_LOCATION]",
    "FAC": "[REDACTED_LOCATION]",
    "NORP": "[REDACTED_AFFILIATION]",
    "DATE": "[REDACTED_DATE]",
    "TIME": "[REDACTED_TIME]",
}

NLP_PIPELINE = None
NLP_PIPELINE_TRIED = False

engine_kwargs = {"future": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

app = FastAPI(title="SafeSpeak X")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_LOGIN_GUARD: dict[str, dict[str, object]] = {}


class Base(DeclarativeBase):
    pass


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sanitized_text: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    redaction_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), default="Low", index=True)
    status: Mapped[str] = mapped_column(String(32), default="Received", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case_access: Mapped["CaseAccess"] = relationship(
        back_populates="report",
        cascade="all, delete-orphan",
        uselist=False,
    )
    attachments: Mapped[list["Attachment"]] = relationship(
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="Attachment.created_at",
    )
    messages: Mapped[list["Message"]] = relationship(
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="Message.created_at",
    )


class CaseAccess(Base):
    __tablename__ = "case_access"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), unique=True, index=True)
    case_code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    passphrase_hash: Mapped[str] = mapped_column(String(255))
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    report: Mapped[Report] = relationship(back_populates="case_access")


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255))
    mime_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    report: Mapped[Report] = relationship(back_populates="attachments")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), index=True)
    sender_role: Mapped[str] = mapped_column(String(32), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    report: Mapped[Report] = relationship(back_populates="messages")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_role: Mapped[str] = mapped_column(String(32), index=True)
    actor_identifier: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(80), index=True)
    report_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    detail: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    detail: Mapped[str] = mapped_column(Text)
    report_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TrackCaseRequest(BaseModel):
    case_code: str = Field(min_length=5, max_length=32)
    passphrase: str = Field(min_length=6, max_length=64)


class AdminLoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class AdminUpdateRequest(BaseModel):
    status: str | None = None
    reply: str | None = None


class AdminLoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in_hours: int


def now() -> datetime:
    return datetime.utcnow()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_secret(secret: str) -> str:
    return pwd_context.hash(secret)


def verify_secret(secret: str, secret_hash: str) -> bool:
    try:
        return pwd_context.verify(secret, secret_hash)
    except Exception:
        return False


def create_access_token(subject: str, role: str) -> str:
    payload = {
        "sub": subject,
        "role": role,
        "exp": now() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip

    return request.client.host if request.client and request.client.host else "unknown"


def login_guard_key(username: str, client_ip: str) -> str:
    return f"{username}|{client_ip}"


def get_login_lock_until(key: str) -> datetime | None:
    record = ADMIN_LOGIN_GUARD.get(key)
    if record is None:
        return None

    now_value = now()
    locked_until = record.get("locked_until")
    if isinstance(locked_until, datetime) and locked_until > now_value:
        return locked_until

    first_failure_at = record.get("first_failure_at")
    if isinstance(first_failure_at, datetime):
        if now_value - first_failure_at > timedelta(minutes=ADMIN_LOGIN_WINDOW_MINUTES):
            ADMIN_LOGIN_GUARD.pop(key, None)
            return None

    if isinstance(locked_until, datetime) and locked_until <= now_value:
        ADMIN_LOGIN_GUARD.pop(key, None)

    return None


def register_login_failure(key: str) -> tuple[int, datetime | None]:
    now_value = now()
    record = ADMIN_LOGIN_GUARD.get(key)

    if record is None:
        record = {
            "failures": 0,
            "first_failure_at": now_value,
            "locked_until": None,
        }
        ADMIN_LOGIN_GUARD[key] = record

    first_failure_at = record.get("first_failure_at")
    if not isinstance(first_failure_at, datetime) or now_value - first_failure_at > timedelta(minutes=ADMIN_LOGIN_WINDOW_MINUTES):
        record["failures"] = 0
        record["first_failure_at"] = now_value
        record["locked_until"] = None

    failures = int(record.get("failures", 0)) + 1
    record["failures"] = failures

    if failures >= ADMIN_LOGIN_MAX_ATTEMPTS:
        locked_until = now_value + timedelta(minutes=ADMIN_LOGIN_LOCKOUT_MINUTES)
        record["locked_until"] = locked_until
        return failures, locked_until

    return failures, None


def clear_login_failures(key: str) -> None:
    ADMIN_LOGIN_GUARD.pop(key, None)


def get_current_admin(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> AdminUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        log_security_event(db, "admin_access_denied", "medium", "Admin API access denied: missing bearer token.")
        db.commit()
        raise HTTPException(status_code=401, detail="Missing admin token.")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError as error:
        log_security_event(db, "admin_access_denied", "medium", "Admin API access denied: invalid or expired token.")
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired admin token.") from error

    if payload.get("role") != "admin":
        log_security_event(db, "admin_access_denied", "high", "Admin API access denied: non-admin role in token.")
        db.commit()
        raise HTTPException(status_code=403, detail="Admin role required.")

    username = payload.get("sub")
    admin = db.scalar(select(AdminUser).where(AdminUser.username == username))
    if admin is None:
        log_security_event(db, "admin_access_denied", "medium", f"Admin API access denied: account not found for {username!s}.")
        db.commit()
        raise HTTPException(status_code=401, detail="Admin account not found.")
    return admin


def log_audit(db: Session, actor_role: str, actor_identifier: str, action: str, detail: str, report_id: int | None = None) -> None:
    db.add(
        AuditLog(
            actor_role=actor_role,
            actor_identifier=actor_identifier,
            action=action,
            detail=detail,
            report_id=report_id,
        )
    )


def log_security_event(
    db: Session,
    event_type: str,
    severity: str,
    detail: str,
    report_id: int | None = None,
) -> None:
    db.add(
        SecurityEvent(
            event_type=event_type,
            severity=severity,
            detail=detail,
            report_id=report_id,
        )
    )


def generate_case_code() -> str:
    year = datetime.utcnow().year
    serial = secrets.randbelow(9000) + 1000
    return f"SS-{year}-{serial}"


def generate_unique_case_code(db: Session, max_attempts: int = 10) -> str:
    for _ in range(max_attempts):
        code = generate_case_code()
        existing = db.scalar(select(CaseAccess.id).where(CaseAccess.case_code == code))
        if existing is None:
            return code
    raise HTTPException(status_code=500, detail="Could not generate a unique case code. Please try again.")


def generate_passphrase() -> str:
    alphabet = string.ascii_uppercase + string.digits
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "-".join(groups)


def truncate_text(text: str, limit: int = 180) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    return compact if len(compact) <= limit else compact[: limit - 1].rstrip() + "…"


def redact_text(text: str) -> tuple[str, list[str]]:
    redactions: list[str] = []
    redacted = text

    nlp = load_nlp_pipeline()
    if nlp is not None:
        doc = nlp(redacted)
        entity_spans: list[tuple[int, int, str, str]] = []
        entity_counts: dict[str, int] = {}

        for entity in doc.ents:
            replacement = NLP_ENTITY_REPLACEMENTS.get(entity.label_)
            if replacement is None:
                continue
            entity_spans.append((entity.start_char, entity.end_char, replacement, entity.label_))
            entity_counts[entity.label_] = entity_counts.get(entity.label_, 0) + 1

        for start, end, replacement, _label in sorted(entity_spans, key=lambda item: item[0], reverse=True):
            redacted = redacted[:start] + replacement + redacted[end:]

        for label, count in sorted(entity_counts.items()):
            redactions.append(f"ml {label.lower()}: {count}")

    substitutions: list[tuple[str, re.Pattern[str], str]] = [
        ("email address", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", re.IGNORECASE), "[REDACTED_EMAIL]"),
        ("phone number", re.compile(r"\b(?:\+?\d[\d\s().-]{7,}\d)\b"), "[REDACTED_PHONE]"),
        ("url", re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE), "[REDACTED_URL]"),
        ("card number", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED_CARD]"),
        (
            "street address",
            re.compile(
                r"\b\d{1,5}\s+[A-Za-z0-9.\- ]{2,40}\s+(Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Boulevard|Blvd|Drive|Dr|Court|Ct|Way|Highway|Hwy)\b",
                re.IGNORECASE,
            ),
            "[REDACTED_ADDRESS]",
        ),
    ]

    for label, pattern, replacement in substitutions:
        redacted, count = pattern.subn(replacement, redacted)
        if count:
            redactions.append(f"{label}: {count}")

    # Explicit name-hint fallback.
    # This protects names that spaCy may miss, including uncommon names,
    # Banglish phrases, and Bangla-script names.
    name_pattern = re.compile(
        r"\b("
        r"(?i:my\s+name\s+is|name\s+is|this\s+is|"
        r"amar\s+nam|amar\s+naam|"
        r"আমার\s+নাম)"
        r")\s+"
        r"("
        r"[^\W\d_][^\W\d_.'’\-]{0,30}"
        r"(?:\s+[^\W\d_][^\W\d_.'’\-]{0,30}){0,2}"
        r")"
        r"(?="
        r"\s+(?i:and|but|from|who|because|ami|amake|amar|apni|uni|se|"
        r"এবং|কিন্তু|আমি|আমাকে|আমার|তিনি|সে)\b"
        r"|[,.!?;:]"
        r"|$"
        r")",
        re.UNICODE,
    )

    def replace_name(match: re.Match[str]) -> str:
        return f"{match.group(1)} [REDACTED_NAME]"

    redacted, count = name_pattern.subn(replace_name, redacted)
    if count:
        redactions.append(f"name hint: {count}")

    return redacted, redactions


def has_meaningful_text(text: str) -> bool:
    cleaned_text = text.strip()
    return bool(cleaned_text) and any(character.isalnum() for character in cleaned_text)


def classify_risk(category: str, text: str, redaction_count: int) -> tuple[int, str]:
    score = 14
    category_score = {
        "abuse": 24,
        "harassment": 20,
        "sexual harassment": 26,
        "domestic violence": 30,
        "stalking": 24,
        "discrimination": 18,
        "workplace abuse": 22,
        "corruption": 18,
        "bribery": 18,
        "fraud": 16,
        "extortion": 22,
        "human rights": 26,
        "human rights violation": 28,
        "police misconduct": 24,
        "cyber harassment": 20,
        "hate speech": 20,
        "other": 8,
    }
    score += category_score.get(category.lower().strip(), 12)

    high_risk_terms = [
        r"\b(kill|murder|rape|assault|weapon|gun|bomb|kidnap|attack|threat|extort|blackmail|stalk)\b",
        r"\b(immediate danger|in danger|life is at risk|fear for my safety)\b",
    ]
    medium_risk_terms = [
        r"\b(unsafe|harass|harassment|bribe|bribery|corruption|discrimination|retaliation|abuse|violence)\b",
        r"\b(racist|sexist|homophobic|stolen|fraud|coercion)\b",
    ]

    for pattern in high_risk_terms:
        if re.search(pattern, text, re.IGNORECASE):
            score += 20

    for pattern in medium_risk_terms:
        if re.search(pattern, text, re.IGNORECASE):
            score += 10

    letters = [character for character in text if character.isalpha()]
    uppercase_ratio = sum(1 for character in letters if character.isupper()) / len(letters) if letters else 0.0
    if uppercase_ratio > 0.35 and len(letters) > 12:
        score += 5

    exclamation_marks = text.count("!")
    if exclamation_marks > 2:
        score += min(8, exclamation_marks * 2)

    if len(text) > 500:
        score += 5

    if redaction_count:
        score += min(12, redaction_count * 3)

    score = max(0, min(100, score))

    if score >= 70:
        return score, "High"
    if score >= 40:
        return score, "Medium"
    return score, "Low"


def build_guidance(risk_level: str, redactions: list[str], category: str) -> list[str]:
    guidance: list[str] = []
    if redactions:
        guidance.append("PII was redacted before storage, so only sanitized text is kept in the database.")
    if any(item.startswith("ml ") for item in redactions):
        guidance.append("spaCy NER detected named entities and replaced them before storage.")
    if risk_level == "High":
        guidance.append("This report has been prioritized for urgent review.")
    elif risk_level == "Medium":
        guidance.append("This report needs prompt review and may need extra evidence.")
    else:
        guidance.append("This report is clear and ready for standard review.")
    guidance.append(f"Category {category.title()} is now tracked anonymously with a secure case code.")
    return guidance


def report_summary(category: str, sanitized_text: str) -> str:
    prefix = f"{category.title()} report: "
    return truncate_text(prefix + sanitized_text, 220)


def serialize_message(message: Message) -> dict[str, str]:
    return {
        "sender_role": message.sender_role,
        "body": message.body,
        "created_at": message.created_at.isoformat(),
    }


def serialize_attachment(attachment: Attachment) -> dict[str, str | int]:
    created_at = attachment.created_at or now()
    return {
        "id": attachment.id,
        "display_name": attachment.display_name,
        "stored_name": attachment.stored_name,
        "mime_type": attachment.mime_type or "",
        "size_bytes": attachment.size_bytes,
        "created_at": created_at.isoformat(),
    }


def serialize_report(report: Report) -> dict[str, object]:
    case_code = report.case_access.case_code if report.case_access else ""
    return {
        "id": report.id,
        "case_code": case_code,
        "category": report.category,
        "title": report.title or "Anonymous report",
        "summary": report.summary,
        "sanitized_text": report.sanitized_text,
        "redaction_count": report.redaction_count,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "status": report.status,
        "location": report.location or "",
        "created_at": report.created_at.isoformat(),
        "updated_at": report.updated_at.isoformat(),
        "attachments": [serialize_attachment(item) for item in report.attachments],
        "messages": [serialize_message(item) for item in report.messages],
    }


def public_stats(db: Session) -> dict[str, int]:
    total_reports = db.scalar(select(func.count(Report.id))) or 0
    open_reports = db.scalar(
        select(func.count(Report.id)).where(Report.status.in_(["Received", "Under Review", "In Progress"]))
    ) or 0
    high_priority = db.scalar(select(func.count(Report.id)).where(Report.risk_level == "High")) or 0
    security_events = db.scalar(select(func.count(SecurityEvent.id))) or 0
    return {
        "total_reports": total_reports,
        "open_reports": open_reports,
        "high_priority": high_priority,
        "security_events": security_events,
    }


def ensure_default_admin(db: Session) -> None:
    existing = db.scalar(select(AdminUser).where(AdminUser.username == DEFAULT_ADMIN_USERNAME))
    if existing is None:
        db.add(AdminUser(username=DEFAULT_ADMIN_USERNAME, password_hash=hash_secret(DEFAULT_ADMIN_PASSWORD)))
        db.commit()


def ensure_tables() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        ensure_default_admin(db)


@app.on_event("startup")
def on_startup() -> None:
    ensure_tables()


@app.get("/", response_class=HTMLResponse)
def read_root() -> str:
    return FRONTEND_INDEX.read_text(encoding="utf-8")


@app.get("/track", response_class=HTMLResponse)
def read_track_page() -> str:
    return FRONTEND_TRACK.read_text(encoding="utf-8")


@app.get("/style.css")
def read_track_stylesheet() -> FileResponse:
    return FileResponse(FRONTEND_STYLE, media_type="text/css")


@app.get("/home-media/{image_key}")
def read_home_showcase_media(image_key: str) -> FileResponse:
    image_path = HOME_SHOWCASE_IMAGES.get(image_key)
    if image_path is None or not image_path.exists():
        raise HTTPException(status_code=404, detail="Image not found.")
    return FileResponse(image_path, media_type="image/jpeg")


@app.get("/submit", response_class=HTMLResponse)
def read_submit_page() -> str:
    return FRONTEND_INDEX.read_text(encoding="utf-8")


@app.get("/report", response_class=HTMLResponse)
def read_report_page() -> str:
    return FRONTEND_INDEX.read_text(encoding="utf-8")


@app.get("/admin", response_class=HTMLResponse)
def read_admin_page() -> str:
    return FRONTEND_INDEX.read_text(encoding="utf-8")


@app.get("/boomboomadminstrator", response_class=HTMLResponse)
def read_admin_legacy_alias() -> str:
    return FRONTEND_INDEX.read_text(encoding="utf-8")


@app.get("/api/health")
def health_check(db: Session = Depends(get_db)) -> dict[str, object]:
    return {
        "status": "ok",
        "app": "SafeSpeak X",
        "database": "connected",
        "stats": public_stats(db),
    }


@app.get("/api/public/stats")
def read_public_stats(db: Session = Depends(get_db)) -> dict[str, int]:
    return public_stats(db)


@app.post("/api/reports")
async def submit_report(
    category: str = Form(...),
    title: str = Form(""),
    details: str = Form(...),
    location: str = Form(""),
    evidence_files: list[UploadFile] | None = File(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    category = category.strip() or "other"
    title = title.strip() or ""
    details = details.strip()
    location = location.strip() or ""

    if not has_meaningful_text(details):
        raise HTTPException(status_code=400, detail="Report details are required and cannot be blank.")

    sanitized_details, redactions = redact_text(details)
    sanitized_title, title_redactions = redact_text(title) if title else ("", [])
    sanitized_location, location_redactions = redact_text(location) if location else ("", [])

    redaction_labels = redactions + title_redactions + location_redactions
    ml_redaction_count = sum(1 for item in redaction_labels if item.startswith("ml "))
    risk_score, risk_level = classify_risk(category, details, len(redaction_labels))
    summary = report_summary(category, sanitized_details)

    report = Report(
        category=category,
        title=sanitized_title or None,
        sanitized_text=sanitized_details,
        summary=summary,
        location=sanitized_location or None,
        redaction_count=len(redaction_labels),
        risk_score=risk_score,
        risk_level=risk_level,
        status="Received",
    )
    db.add(report)
    db.flush()

    case_code = generate_unique_case_code(db)
    passphrase = generate_passphrase()
    case_access = CaseAccess(
        report_id=report.id,
        case_code=case_code,
        passphrase_hash=hash_secret(passphrase),
    )
    report.case_access = case_access
    report.messages.append(
        Message(
            sender_role="system",
            body="Your report has been received, sanitized, and queued for secure review.",
        )
    )

    attachment_payloads: list[dict[str, object]] = []
    for index, upload in enumerate(evidence_files or [], start=1):
        original_filename = Path(upload.filename or f"evidence_{index}").name
        suffix = Path(original_filename).suffix or ".bin"
        stored_name = f"report_{report.id}_evidence_{index}{suffix}"
        destination = UPLOAD_DIR / f"report_{report.id}"
        destination.mkdir(parents=True, exist_ok=True)
        target_path = destination / stored_name
        content = await upload.read()
        target_path.write_bytes(content)

        attachment = Attachment(
    report_id=report.id,
    display_name=f"Evidence {index}{suffix}",
    stored_name=stored_name,
    mime_type=upload.content_type,
    size_bytes=len(content),
    created_at=now(),
)
        report.attachments.append(attachment)
        attachment_payloads.append(serialize_attachment(attachment))

    guidance = build_guidance(risk_level, redaction_labels, category)
    log_audit(db, "public", "anonymous", "report_submitted", f"Anonymous report submitted with risk {risk_level}", report.id)
    if redaction_labels:
        log_security_event(
            db,
            "pii_redaction",
            "low" if len(redaction_labels) < 3 else "medium",
            "; ".join(redaction_labels),
            report.id,
        )

    db.commit()
    db.refresh(report)

    return {
        "report": serialize_report(report),
        "case_code": case_code,
        "passphrase": passphrase,
        "track_url": f"/track?case={case_code}",
        "guidance": guidance,
        "redactions": redaction_labels,
        "ml_redaction_count": ml_redaction_count,
        "redaction_engine": "spaCy NER + regex" if load_nlp_pipeline() is not None else "regex fallback",
        "attachment_count": len(attachment_payloads),
        "tracking_hint": "Keep the case code and passphrase together to track your report later.",
    }


@app.post("/api/cases/track")
def track_case(payload: TrackCaseRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    code = payload.case_code.strip().upper()
    case_access = db.scalar(select(CaseAccess).where(CaseAccess.case_code == code))
    if case_access is None:
        log_security_event(db, "track_failed", "medium", f"Unknown case code attempted: {code}")
        db.commit()
        raise HTTPException(status_code=404, detail="Case not found.")

    now_value = now()
    if case_access.locked_until and case_access.locked_until > now_value:
        log_security_event(db, "track_locked", "high", f"Locked case code requested: {code}", case_access.report_id)
        db.commit()
        raise HTTPException(status_code=429, detail="Tracking is temporarily locked. Try again later.")

    if not verify_secret(payload.passphrase, case_access.passphrase_hash):
        case_access.failed_attempts += 1
        if case_access.failed_attempts >= 5:
            case_access.locked_until = now_value + timedelta(minutes=15)
        log_security_event(
            db,
            "track_failed",
            "medium" if case_access.failed_attempts < 5 else "high",
            f"Invalid passphrase attempted for {code}",
            case_access.report_id,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid case code or passphrase.")

    case_access.failed_attempts = 0
    case_access.locked_until = None
    case_access.last_accessed_at = now_value
    report = case_access.report
    log_audit(db, "anonymous", code, "case_tracked", "Anonymous user viewed their report status.", report.id)
    db.commit()

    messages = [serialize_message(item) for item in report.messages]
    timeline = [
        {"label": "Submitted", "value": report.created_at.isoformat()},
        {"label": "Sanitized", "value": report.updated_at.isoformat()},
        {"label": "Current status", "value": report.status},
    ]

    return {
        "case_code": code,
        "track_url": f"/track?case={code}",
        "report": serialize_report(report),
        "messages": messages,
        "timeline": timeline,
        "attachments": [serialize_attachment(item) for item in report.attachments],
    }


@app.post("/api/admin/login")
def admin_login(
    payload: AdminLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AdminLoginResponse:
    username = payload.username.strip().lower()
    client_ip = get_client_ip(request)
    guard_key = login_guard_key(username, client_ip)

    locked_until = get_login_lock_until(guard_key)
    if locked_until is not None:
        minutes_remaining = max(1, int((locked_until - now()).total_seconds() // 60) + 1)
        log_security_event(
            db,
            "admin_login_locked",
            "high",
            f"Blocked admin login for {username} from {client_ip}: lock active for {minutes_remaining} more minute(s).",
        )
        db.commit()
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    admin = db.scalar(select(AdminUser).where(AdminUser.username == username))
    if admin is None or not verify_secret(payload.password, admin.password_hash):
        failures, new_lock_until = register_login_failure(guard_key)
        if new_lock_until is not None:
            log_security_event(
                db,
                "admin_login_locked",
                "high",
                f"Admin login locked for {username} from {client_ip} after {failures} failed attempts.",
            )
            db.commit()
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

        attempts_left = max(0, ADMIN_LOGIN_MAX_ATTEMPTS - failures)
        log_security_event(
            db,
            "admin_login_failed",
            "medium",
            f"Failed admin login for {username} from {client_ip}. Attempts left before lock: {attempts_left}.",
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")

    clear_login_failures(guard_key)
    token = create_access_token(username, "admin")
    log_security_event(db, "admin_login_success", "low", f"Admin login successful for {username} from {client_ip}")
    log_audit(db, "admin", username, "admin_login", "Admin authenticated successfully.")
    db.commit()
    return AdminLoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in_hours=ACCESS_TOKEN_EXPIRE_HOURS,
    )


@app.get("/api/admin/dashboard")
def admin_dashboard(
    current_admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    reports = db.execute(select(Report).order_by(Report.created_at.desc())).scalars().all()
    security_events = db.execute(
        select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(ADMIN_SECURITY_EVENT_LIMIT)
    ).scalars().all()
    audit_logs = db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(ADMIN_AUDIT_LOG_LIMIT)).scalars().all()

    security_report_ids = sorted({event.report_id for event in security_events if event.report_id is not None})
    case_codes_by_report: dict[int, str] = {}
    if security_report_ids:
        case_rows = db.execute(
            select(CaseAccess.report_id, CaseAccess.case_code).where(CaseAccess.report_id.in_(security_report_ids))
        ).all()
        case_codes_by_report = {int(report_id): case_code for report_id, case_code in case_rows}

    redaction_events_by_report: dict[int, str] = {}
    for event in security_events:
        if event.event_type == "pii_redaction" and event.report_id is not None and event.report_id not in redaction_events_by_report:
            redaction_events_by_report[event.report_id] = event.detail

    report_payloads: list[dict[str, object]] = []
    for report in reports:
        payload = serialize_report(report)
        redaction_detail = redaction_events_by_report.get(report.id, "")
        redaction_labels = [item.strip() for item in redaction_detail.split(";") if item.strip()]
        ml_redaction_count = sum(1 for item in redaction_labels if item.startswith("ml "))
        payload["redaction_labels"] = redaction_labels
        payload["ml_redaction_count"] = ml_redaction_count
        payload["redaction_engine"] = "spaCy NER + regex" if ml_redaction_count else "regex fallback"
        report_payloads.append(payload)

    return {
        "admin": current_admin.username,
        "stats": public_stats(db),
        "reports": report_payloads,
        "security_events": [
            {
                "event_type": event.event_type,
                "severity": event.severity,
                "detail": event.detail,
                "report_id": event.report_id,
                "case_code": case_codes_by_report.get(event.report_id) if event.report_id is not None else None,
                "created_at": event.created_at.isoformat(),
            }
            for event in security_events
        ],
        "audit_logs": [
            {
                "actor_role": log.actor_role,
                "actor_identifier": log.actor_identifier,
                "action": log.action,
                "detail": log.detail,
                "report_id": log.report_id,
                "created_at": log.created_at.isoformat(),
            }
            for log in audit_logs
        ],
    }


@app.get("/api/admin/attachments/{attachment_id}")
def download_attachment(
    attachment_id: int,
    current_admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> FileResponse:
    attachment = db.get(Attachment, attachment_id)
    if attachment is None:
        raise HTTPException(status_code=404, detail="Attachment not found.")

    file_path = UPLOAD_DIR / f"report_{attachment.report_id}" / attachment.stored_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found.")

    return FileResponse(
        file_path,
        media_type=attachment.mime_type or "application/octet-stream",
        filename=attachment.display_name,
    )


@app.patch("/api/admin/reports/{report_id}")
def update_report(
    report_id: int,
    payload: AdminUpdateRequest,
    current_admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")

    allowed_statuses = {"Received", "Under Review", "In Progress", "Resolved", "Closed"}
    changes: list[str] = []
    status_change_detail: str | None = None
    reply_text: str | None = None

    if payload.status is not None:
        status_value = payload.status.strip()
        if status_value not in allowed_statuses:
            raise HTTPException(status_code=400, detail="Unsupported report status.")
        if status_value != report.status:
            previous_status = report.status
            report.status = status_value
            status_change_detail = f"status: {previous_status} -> {status_value}"
            changes.append(status_change_detail)

    if payload.reply is not None and payload.reply.strip():
        reply_text = payload.reply.strip()
        report.messages.append(Message(sender_role="admin", body=reply_text))
        changes.append("reply added")

    report.updated_at = now()

    if status_change_detail is not None:
        log_security_event(db, "admin_status_changed", "low", status_change_detail, report.id)
        log_audit(db, "admin", current_admin.username, "report_status_updated", status_change_detail, report.id)

    if reply_text is not None:
        log_security_event(
            db,
            "admin_reply_added",
            "low",
            f"Admin reply added ({len(reply_text)} chars).",
            report.id,
        )
        log_audit(
            db,
            "admin",
            current_admin.username,
            "report_reply_added",
            f"Admin reply posted ({len(reply_text)} chars): {truncate_text(reply_text, 120)}",
            report.id,
        )

    log_audit(db, "admin", current_admin.username, "report_updated", "; ".join(changes) or "No changes provided.", report.id)
    db.commit()
    db.refresh(report)

    return serialize_report(report)


@app.get("/api/admin/security-events")
def admin_security_events(
    current_admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    events = db.execute(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(ADMIN_SECURITY_EVENT_LIMIT)).scalars().all()
    event_report_ids = sorted({event.report_id for event in events if event.report_id is not None})
    case_codes_by_report: dict[int, str] = {}
    if event_report_ids:
        case_rows = db.execute(
            select(CaseAccess.report_id, CaseAccess.case_code).where(CaseAccess.report_id.in_(event_report_ids))
        ).all()
        case_codes_by_report = {int(report_id): case_code for report_id, case_code in case_rows}

    return {
        "events": [
            {
                "event_type": event.event_type,
                "severity": event.severity,
                "detail": event.detail,
                "report_id": event.report_id,
                "case_code": case_codes_by_report.get(event.report_id) if event.report_id is not None else None,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ]
    }


@app.get("/panic", response_class=HTMLResponse)
def panic_exit() -> str:
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Community Resources</title>
    <style>
        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            font-family: Arial, sans-serif;
            background: linear-gradient(180deg, #f8fafc, #eef2f7);
            color: #162033;
        }
        .card {
            width: min(90vw, 720px);
            padding: 32px;
            border-radius: 24px;
            background: rgba(255, 255, 255, 0.96);
            box-shadow: 0 20px 60px rgba(20, 30, 50, 0.14);
        }
        h1 {
            margin-top: 0;
            font-size: 2rem;
        }
        p {
            line-height: 1.7;
            color: #4c596f;
        }
        .links {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 24px;
        }
        a {
            color: #0b5cab;
            text-decoration: none;
            font-weight: 700;
        }
    </style>
</head>
<body>
    <main class="card">
        <h1>Community Resources</h1>
        <p>This page is intentionally neutral. It is a safe place to continue browsing without exposing the previous session.</p>
        <p>If you need support, use the links below to continue with general resources.</p>
        <div class="links">
            <a href="https://www.wikipedia.org/" rel="noreferrer">Wikipedia</a>
            <a href="https://www.un.org/" rel="noreferrer">United Nations</a>
            <a href="https://www.google.com/" rel="noreferrer">Search</a>
        </div>
    </main>
</body>
</html>
"""
