import hashlib
import os
import re
import secrets
from datetime import datetime
from typing import Optional, Tuple

from authlib.integrations.starlette_client import OAuth
from fastapi import Body, Depends, FastAPI, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from packaging.version import parse as parse_version
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine, event, text, and_, or_, false
from sqlalchemy.exc import IntegrityError
from starlette.middleware.sessions import SessionMiddleware
from models import Base, User, Team, APIKey, Device, Firmware, Label, UserRole, ScopeType, CarrierBoard, FirmwareRelease, ApplicationGroup, AllowedEmail, AllowedDomain
from auth import (
    oauth, hash_api_key, get_current_user_from_db, verify_api_key,
    get_current_user_scopes, verify_api_key_scope_access
)

# =============================================================================
app = FastAPI(title="ESP32 Fleet OTA Server")

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    accept = request.headers.get("accept", "")
    if "text/html" in accept and not request.url.path.startswith("/admin/upload") and not request.url.path.startswith("/check-update"):
        return HTMLResponse(
            status_code=exc.status_code,
            content=f"""
            <html>
                <body style="font-family: sans-serif; text-align: center; padding-top: 100px; background: #f9fafb; color: #333;">
                    <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                        <h1 style="color: #ef4444; margin-top: 0;">Access Denied</h1>
                        <p>{exc.detail}</p>
                        <a href="/login" style="display: inline-block; margin-top: 15px; color: #3b82f6; text-decoration: none;">Return to Login</a>
                    </div>
                </body>
            </html>
            """
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", secrets.token_urlsafe(32))
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

DATA_DIR = "/app/data"
FIRMWARE_DIR = os.path.join(DATA_DIR, "firmware")
os.makedirs(FIRMWARE_DIR, exist_ok=True)

DEFAULT_CARRIER_BOARD_NAME = "Breadboard"
DEFAULT_CARRIER_BOARD_DESCRIPTION = "Wildcard prototyping profile for dev rigs and breadboard builds."

# =============================================================================
# Database Setup
# =============================================================================
DATABASE_URL = f"sqlite:///{os.path.join(DATA_DIR, 'ota.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Apply WAL journal mode so concurrent device check-ins don't block reads.
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def _migrate_legacy_sqlite_schema() -> None:
    """
    Backfill columns expected by current ORM models for existing SQLite deployments.
    SQLAlchemy create_all() does not ALTER existing tables, so persisted DBs from
    older app versions can miss newer columns and cause runtime 500s.
    """
    with engine.begin() as conn:
        table_info = conn.execute(text("PRAGMA table_info(devices)"))
        existing_columns = {row[1] for row in table_info.fetchall()}

        # Only additive, idempotent migrations to keep startup safe in production.
        if "nickname" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN nickname VARCHAR"))
        if "battery" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN battery INTEGER"))
        if "last_ota_status" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN last_ota_status VARCHAR"))
        if "claimed" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN claimed BOOLEAN NOT NULL DEFAULT 0"))
        if "scope_id" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN scope_id INTEGER"))
        if "scope_type" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN scope_type VARCHAR(8)"))
        if "compute_module" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN compute_module VARCHAR"))
        if "class_name" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN class_name VARCHAR"))
        if "group_name" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN group_name VARCHAR"))
        if "carrier_board_id" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN carrier_board_id INTEGER"))
        if "application_group_id" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN application_group_id INTEGER"))
        if "firmware_override_id" not in existing_columns:
            conn.execute(text("ALTER TABLE devices ADD COLUMN firmware_override_id INTEGER"))

        firmware_release_table_info = conn.execute(text("PRAGMA table_info(firmware_releases)"))
        firmware_release_columns = {row[1] for row in firmware_release_table_info.fetchall()}

        carrier_board_table_info = conn.execute(text("PRAGMA table_info(carrier_boards)"))
        carrier_board_columns = {row[1] for row in carrier_board_table_info.fetchall()}
        if "description" not in carrier_board_columns:
            conn.execute(text("ALTER TABLE carrier_boards ADD COLUMN description VARCHAR"))

        if "firmware_name" not in firmware_release_columns:
            conn.execute(text("ALTER TABLE firmware_releases ADD COLUMN firmware_name VARCHAR"))
        if "firmware_version" not in firmware_release_columns:
            conn.execute(text("ALTER TABLE firmware_releases ADD COLUMN firmware_version VARCHAR"))
        if "compute_module" not in firmware_release_columns:
            conn.execute(text("ALTER TABLE firmware_releases ADD COLUMN compute_module VARCHAR"))
        if "carrier_board_id" not in firmware_release_columns:
            conn.execute(text("ALTER TABLE firmware_releases ADD COLUMN carrier_board_id INTEGER"))

        # Backfill newly introduced naming/versioning columns from legacy schema.
        if "version" in firmware_release_columns:
            conn.execute(text("UPDATE firmware_releases SET firmware_version = version WHERE firmware_version IS NULL OR firmware_version = ''"))
        application_group_table_info = conn.execute(text("PRAGMA table_info(application_groups)"))
        application_group_columns = {row[1] for row in application_group_table_info.fetchall()}

        if "target_firmware_name" not in application_group_columns:
            conn.execute(text("ALTER TABLE application_groups ADD COLUMN target_firmware_name VARCHAR"))
        if "target_firmware_version" not in application_group_columns:
            conn.execute(text("ALTER TABLE application_groups ADD COLUMN target_firmware_version VARCHAR"))

        if "target_release_id" not in application_group_columns:
            conn.execute(text("ALTER TABLE application_groups ADD COLUMN target_release_id INTEGER"))

        api_key_table_info = conn.execute(text("PRAGMA table_info(api_keys)"))
        api_key_columns = {row[1] for row in api_key_table_info.fetchall()}

        if "user_id" not in api_key_columns:
            conn.execute(text("ALTER TABLE api_keys ADD COLUMN user_id INTEGER"))

        if "owner_id" not in api_key_columns:
            conn.execute(text("ALTER TABLE api_keys ADD COLUMN owner_id INTEGER"))

        if "key_suffix" not in api_key_columns:
            conn.execute(text("ALTER TABLE api_keys ADD COLUMN key_suffix VARCHAR(8)"))

        if "label" not in api_key_columns:
            conn.execute(text("ALTER TABLE api_keys ADD COLUMN label VARCHAR"))

        if "last_used_at" not in api_key_columns:
            conn.execute(text("ALTER TABLE api_keys ADD COLUMN last_used_at DATETIME"))

        if "owner_id" in api_key_columns:
            conn.execute(text("UPDATE api_keys SET user_id = owner_id WHERE user_id IS NULL"))
            conn.execute(text("UPDATE api_keys SET owner_id = user_id WHERE owner_id IS NULL"))


_migrate_legacy_sqlite_schema()


def _seed_default_carrier_board() -> None:
    """
    Ensure a wildcard carrier board always exists for prototyping workflows.
    Also upgrades legacy naming from "Dev/Any (Prototyping)" to "Breadboard".
    """
    db = SessionLocal()
    try:
        board = db.query(CarrierBoard).filter(CarrierBoard.name == DEFAULT_CARRIER_BOARD_NAME).first()
        legacy = db.query(CarrierBoard).filter(CarrierBoard.name == "Dev/Any (Prototyping)").first()

        if not board and legacy:
            legacy.name = DEFAULT_CARRIER_BOARD_NAME
            legacy.description = legacy.description or DEFAULT_CARRIER_BOARD_DESCRIPTION
            db.commit()
            return

        if not board:
            # Backward compatibility: some persisted DBs still have a required
            # carrier_boards.tags column from older schemas.
            board_cols = db.execute(text("PRAGMA table_info(carrier_boards)")).fetchall()
            tags_is_required = any((row[1] == "tags" and int(row[3]) == 1) for row in board_cols)
            if tags_is_required:
                db.execute(
                    text("INSERT INTO carrier_boards (name, description, tags) VALUES (:name, :description, :tags)"),
                    {
                        "name": DEFAULT_CARRIER_BOARD_NAME,
                        "description": DEFAULT_CARRIER_BOARD_DESCRIPTION,
                        "tags": "[]",
                    },
                )
            else:
                db.add(CarrierBoard(
                    name=DEFAULT_CARRIER_BOARD_NAME,
                    description=DEFAULT_CARRIER_BOARD_DESCRIPTION,
                ))
            db.commit()
            return

        if not board.description:
            board.description = DEFAULT_CARRIER_BOARD_DESCRIPTION
            db.commit()
    finally:
        db.close()

# =============================================================================
# Access Allowlist: Bootstrap from Env Var on First Run
# =============================================================================
def _seed_allowlist_from_env():
    """
    On startup:
    1) inject any emails from ADMIN_EMAILS into the allowlist table, and
    2) reconcile existing users so listed emails are Admin.

    This prevents role drift when ADMIN_EMAILS changes after users were
    already created in earlier deployments.
    """
    if not ADMIN_EMAILS:
        return
    db = SessionLocal()
    try:
        for email in ADMIN_EMAILS:
            if not db.query(AllowedEmail).filter(AllowedEmail.email == email).first():
                db.add(AllowedEmail(email=email, note="Seeded from ADMIN_EMAILS env var"))
            user = db.query(User).filter(User.email == email).first()
            if user and user.role != UserRole.Admin:
                user.role = UserRole.Admin
        db.commit()
    finally:
        db.close()


def _is_email_allowed(email: str, db: Session) -> bool:
    """Check if a normalized (lowercase) email is permitted by the DB allowlist."""
    if db.query(AllowedEmail).filter(AllowedEmail.email == email).first():
        return True
    domain = email.split("@")[-1] if "@" in email else ""
    if domain and db.query(AllowedDomain).filter(AllowedDomain.domain == domain).first():
        return True
    return False

# =============================================================================
# Shared Helpers
# =============================================================================
templates = Jinja2Templates(directory="templates")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
) -> User:
    """
    Dual auth resolution:
    1) Authorization: Bearer <token>
    2) OAuth session fallback
    """
    if authorization:
        scheme, _, raw_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not raw_token.strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format. Expected: Bearer <token>.",
            )

        key_hash = hash_api_key(raw_token.strip())
        api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid personal access token.",
            )
        if not api_key.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is not bound to a valid user.",
            )
        api_key.last_used_at = datetime.utcnow()
        db.commit()
        return api_key.user

    return get_current_user_from_db(request, db)

def require_admin_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db, request.headers.get("Authorization"))
    if user.role != UserRole.Admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin privileges required.",
        )
    return user

def require_admin_actor(
    request: Request,
    db: Session = Depends(get_db),
    x_admin_key: Optional[str] = Header(default=None),
) -> User:
    """
    Allows either an authenticated Admin web session or an Admin-owned API key.
    """
    if x_admin_key:
        key_hash = hash_api_key(x_admin_key)
        api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
        if not api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key.")
        if api_key.user.role != UserRole.Admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin API key required.")
        api_key.last_used_at = datetime.utcnow()
        db.commit()
        return api_key.user
    return require_admin_user(request, db)

def _scope_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")


def _resolve_scope_selection(scope: str, user: User, db: Session) -> Tuple[ScopeType, int, str]:
    scope_slug = _scope_slug(scope)
    if scope_slug == "personal":
        return ScopeType.Personal, user.id, "Personal"

    team = None
    for t in db.query(Team).all():
        if _scope_slug(t.name) == scope_slug:
            team = t
            break

    if not team:
        raise HTTPException(status_code=400, detail="Unknown scope.")

    return ScopeType.Team, team.id, team.name


def _has_scope_access(user: User, scope_type: ScopeType, scope_id: int) -> bool:
    if user.role == UserRole.Admin:
        return True
    return (scope_type, scope_id) in get_current_user_scopes(user=user)


def _can_manage_device(user: User, device: Device) -> bool:
    if user.role == UserRole.Admin:
        return True
    if not device.scope_type or device.scope_id is None:
        return False
    return (device.scope_type, device.scope_id) in get_current_user_scopes(user=user)


def _parse_optional_int(value: Optional[str], field_name: str) -> Optional[int]:
    if value is None:
        return None
    cleaned = value.strip()
    if cleaned == "":
        return None
    try:
        return int(cleaned)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}.")


def _upsert_labels_for_device(device: Device, labels_csv: str, db: Session) -> None:
    parsed_labels = [l.strip().lower() for l in (labels_csv or "").split(",") if l.strip()]
    if not parsed_labels:
        device.labels = []
        return

    existing = db.query(Label).filter(Label.name.in_(parsed_labels)).all()
    existing_by_name = {lbl.name: lbl for lbl in existing}
    resolved_labels = []

    for name in parsed_labels:
        lbl = existing_by_name.get(name)
        if not lbl:
            lbl = Label(name=name, color="#3b82f6")
            db.add(lbl)
            existing_by_name[name] = lbl
        resolved_labels.append(lbl)

    device.labels = resolved_labels


def _device_scope_label(device: Device, user: User, team_name_by_id: dict[int, str]) -> str:
    if device.scope_type == ScopeType.Personal:
        return "Personal"
    if device.scope_type == ScopeType.Team:
        return team_name_by_id.get(device.scope_id, "Team")
    return "Unassigned"


def _device_scope_slug(device: Device, team_name_by_id: dict[int, str]) -> str:
    if device.scope_type == ScopeType.Personal:
        return "personal"
    if device.scope_type == ScopeType.Team:
        return _scope_slug(team_name_by_id.get(device.scope_id, "team"))
    return ""

def is_newer_version(v1: str, v2: str) -> bool:
    """Returns True if v1 is semantically newer than v2."""
    try:
        return parse_version(v1) > parse_version(v2)
    except Exception:
        return False

def _sanitize_field(value: str, allow_dots: bool = False) -> str:
    """Strip characters that could enable path traversal or injection."""
    pattern = r"[^a-zA-Z0-9_\-\.]" if allow_dots else r"[^a-zA-Z0-9_\-]"
    return re.sub(pattern, "", value)


def _normalize_firmware_name(value: Optional[str]) -> str:
    return (value or "").strip()


def _normalize_firmware_version(value: Optional[str]) -> str:
    return (value or "").strip()


def _evaluate_group_readiness(group: ApplicationGroup, firmware_name: str, firmware_version: str, db: Session) -> dict:
    normalized_name = _normalize_firmware_name(firmware_name)
    normalized_version = _normalize_firmware_version(firmware_version)

    unknown_hardware_count = db.query(Device.id).filter(
        Device.application_group_id == group.id,
        Device.claimed == True,
        or_(
            Device.compute_module.is_(None),
            Device.compute_module == "",
            Device.carrier_board_id.is_(None),
        ),
    ).count()

    combo_rows = db.query(Device.compute_module, Device.carrier_board_id).filter(
        Device.application_group_id == group.id,
        Device.claimed == True,
        Device.compute_module.isnot(None),
        Device.compute_module != "",
        Device.carrier_board_id.isnot(None),
    ).distinct().all()

    required_combos = [
        {"compute_module": compute_module, "carrier_board_id": carrier_board_id}
        for compute_module, carrier_board_id in combo_rows
    ]

    if unknown_hardware_count > 0:
        return {
            "group_id": group.id,
            "firmware_name": normalized_name,
            "firmware_version": normalized_version,
            "status": "Preparing",
            "ready": False,
            "required_combos": required_combos,
            "missing_combos": required_combos,
            "unknown_hardware_count": unknown_hardware_count,
        }

    if not required_combos:
        return {
            "group_id": group.id,
            "firmware_name": normalized_name,
            "firmware_version": normalized_version,
            "status": "Preparing",
            "ready": False,
            "required_combos": [],
            "missing_combos": [],
            "unknown_hardware_count": 0,
        }

    if not normalized_name or not normalized_version:
        return {
            "group_id": group.id,
            "firmware_name": normalized_name,
            "firmware_version": normalized_version,
            "status": "Preparing",
            "ready": False,
            "required_combos": required_combos,
            "missing_combos": required_combos,
            "unknown_hardware_count": 0,
        }

    missing_combos = []
    for combo in required_combos:
        has_payload = db.query(FirmwareRelease.id).filter(
            FirmwareRelease.firmware_name == normalized_name,
            FirmwareRelease.firmware_version == normalized_version,
            FirmwareRelease.compute_module == combo["compute_module"],
            FirmwareRelease.carrier_board_id == combo["carrier_board_id"],
        ).first()
        if not has_payload:
            missing_combos.append(combo)

    return {
        "group_id": group.id,
        "firmware_name": normalized_name,
        "firmware_version": normalized_version,
        "status": "Ready" if not missing_combos else "Preparing",
        "ready": len(missing_combos) == 0,
        "required_combos": required_combos,
        "missing_combos": missing_combos,
        "unknown_hardware_count": 0,
    }


# =============================================================================
# Request Schemas
# =============================================================================

class AssignLabelsRequest(BaseModel):
    label_ids: list[int]

class TeamCreateRequest(BaseModel):
    name: str

class TeamAssignRequest(BaseModel):
    user_email: str
    team_id: int


# =============================================================================
# Google OAuth Routes
# =============================================================================

GOOGLE_OAUTH_REDIRECT_URI = os.getenv("GOOGLE_OAUTH_REDIRECT_URI")
# Comma-separated allowlist used ONLY to seed the database on first run.
ADMIN_EMAILS = set(e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip())

@app.on_event("startup")
def startup_seed_defaults() -> None:
    _seed_allowlist_from_env()
    _seed_default_carrier_board()

@app.get("/login", include_in_schema=False)
async def login(request: Request):
    """Redirect the browser to Google's OAuth 2.0 consent screen."""
    if not GOOGLE_OAUTH_REDIRECT_URI:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GOOGLE_OAUTH_REDIRECT_URI is not configured.",
        )
    return await oauth.google.authorize_redirect(request, GOOGLE_OAUTH_REDIRECT_URI)


@app.get("/auth", name="auth_callback", include_in_schema=False)
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    """
    Google OAuth callback handler.
    Exchanges the authorization code for tokens, retrieves the user profile,
    enforces the ADMIN_EMAILS whitelist, upserts the User record, and
    stores minimal user info in the encrypted session cookie.
    """
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authorization failed. Error: {str(e)}",
        )

    user_info = token.get("userinfo")
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve user info from Google.",
        )

    email = user_info.get("email", "").strip().lower()

    # Enforce the allowlist against the live database (supports domain wildcards).
    if not _is_email_allowed(email, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {email} is not on the authorized access list.",
        )

    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Give admin role if email is in the ADMIN_EMAILS allowlist.
        role = UserRole.Admin if email in ADMIN_EMAILS else UserRole.User
        user = User(email=email, name=user_info.get("name", ""), role=role)
        db.add(user)
        db.commit()
    elif email in ADMIN_EMAILS and user.role != UserRole.Admin:
        # Promote legacy records created before ADMIN_EMAILS included this user.
        user.role = UserRole.Admin
        db.commit()

    request.session["user"] = {"email": email, "name": user_info.get("name", ""), "role": user.role.value}
    return RedirectResponse(url="/dashboard")


@app.get("/logout", include_in_schema=False)
async def logout(request: Request):
    """Clear the session cookie and redirect to /login."""
    request.session.clear()
    return RedirectResponse(url="/login")


# Convenience redirect from root.
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/dashboard")


# =============================================================================
# Human Web Portal — Dashboard (OAuth-protected)
# =============================================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Main Flight Deck dashboard. Requires authentication."""
    session_user = request.session.get("user")
    if not session_user:
        return RedirectResponse(url="/login")

    user_info = get_current_user(request, db, request.headers.get("Authorization"))

    # Keep session role in sync with the DB in case roles were reconciled
    # during startup or by later admin operations.
    session_user["role"] = user_info.role.value
    request.session["user"] = session_user

    if user_info.role == UserRole.Admin:
        visible_claimed_devices = db.query(Device).filter(Device.claimed == True).all()
        scope_options = [{"value": "personal", "label": "Personal (Isolated)"}] + [
            {"value": _scope_slug(team.name), "label": team.name}
            for team in db.query(Team).order_by(Team.name.asc()).all()
        ]
    else:
        team_ids = [t.id for t in user_info.teams]
        scope_filter = or_(
            and_(Device.scope_type == ScopeType.Team, Device.scope_id.in_(team_ids) if team_ids else false()),
            and_(Device.scope_type == ScopeType.Personal, Device.scope_id == user_info.id),
        )
        visible_claimed_devices = db.query(Device).filter(Device.claimed == True, scope_filter).all()
        scope_options = [{"value": "personal", "label": "Personal (Isolated)"}] + [
            {"value": _scope_slug(team.name), "label": team.name}
            for team in sorted(user_info.teams, key=lambda t: t.name.lower())
        ]

    unclaimed_devices = db.query(Device).filter(Device.claimed == False).all()
    firmware_releases = db.query(FirmwareRelease).order_by(FirmwareRelease.id.desc()).all()
    teams = db.query(Team).all()
    team_name_by_id = {team.id: team.name for team in teams}

    fleet_nodes = []
    for device in visible_claimed_devices:
        labels = [lbl.name for lbl in (device.labels or [])]
        last_checkin = device.last_checkin
        is_online = bool(last_checkin and (datetime.utcnow() - last_checkin).total_seconds() <= 900)
        fleet_nodes.append({
            "mac": device.mac_address,
            "scope": _device_scope_label(device, user_info, team_name_by_id),
            "scope_slug": _device_scope_slug(device, team_name_by_id),
            "labels": labels,
            "labels_csv": ", ".join(labels),
            "fw": device.version or "unknown",
            "batt": int(device.battery) if device.battery is not None else 0,
            "status": "online" if is_online else "offline",
            "carrier_board_id": device.carrier_board_id,
            "firmware_override_id": device.firmware_override_id,
        })

    unclaimed_rows = [
        {
            "mac_address": d.mac_address,
            "last_seen": d.last_checkin.isoformat() if d.last_checkin else "Unknown",
        }
        for d in unclaimed_devices
    ]

    api_tokens = db.query(APIKey).filter(APIKey.user_id == user_info.id).order_by(APIKey.id.desc()).all()
    new_key  = request.session.pop("new_key_flash", None)
    carrier_boards = db.query(CarrierBoard).order_by(CarrierBoard.name.asc()).all()
    application_groups = db.query(ApplicationGroup).order_by(ApplicationGroup.name.asc()).all()

    firmware_versions_by_name: dict[str, list[str]] = {}
    all_release_rows = db.query(FirmwareRelease).order_by(FirmwareRelease.id.desc()).all()
    for release in all_release_rows:
        name = _normalize_firmware_name(release.firmware_name)
        version = _normalize_firmware_version(release.firmware_version)
        if not name or not version:
            continue
        if name not in firmware_versions_by_name:
            firmware_versions_by_name[name] = []
        if version not in firmware_versions_by_name[name]:
            firmware_versions_by_name[name].append(version)

    for name, versions in firmware_versions_by_name.items():
        firmware_versions_by_name[name] = sorted(
            versions,
            key=lambda value: parse_version(value),
            reverse=True,
        )

    firmware_names = sorted(firmware_versions_by_name.keys(), key=lambda value: value.lower())

    staging_rows = []
    for group in application_groups:
        current_target_name = _normalize_firmware_name(group.target_firmware_name)
        current_target_version = _normalize_firmware_version(group.target_firmware_version)
        if group.target_release:
            if not current_target_name:
                current_target_name = _normalize_firmware_name(group.target_release.firmware_name)
            if not current_target_version:
                current_target_version = _normalize_firmware_version(group.target_release.firmware_version)

        staged_firmware_name = current_target_name or (firmware_names[0] if firmware_names else "")
        available_versions = firmware_versions_by_name.get(staged_firmware_name, [])
        staged_firmware_version = current_target_version or (available_versions[0] if available_versions else "")
        readiness = _evaluate_group_readiness(group, staged_firmware_name, staged_firmware_version, db)

        staging_rows.append({
            "group": group,
            "current_target_firmware_name": current_target_name,
            "current_target_firmware_version": current_target_version,
            "staged_firmware_name": staged_firmware_name,
            "staged_firmware_version": staged_firmware_version,
            "readiness": readiness,
        })

    allowed_emails  = db.query(AllowedEmail).order_by(AllowedEmail.created_at).all()  if user_info.role == UserRole.Admin else []
    allowed_domains = db.query(AllowedDomain).order_by(AllowedDomain.created_at).all() if user_info.role == UserRole.Admin else []
    admin_api_tokens = db.query(APIKey).join(User).order_by(APIKey.created_at.desc()).all() if user_info.role == UserRole.Admin else []
    admin_teams = db.query(Team).order_by(Team.name.asc()).all() if user_info.role == UserRole.Admin else []
    admin_users = db.query(User).order_by(User.email.asc()).all() if user_info.role == UserRole.Admin else []

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user":            session_user,
            "db_user":         user_info,
            "devices":         visible_claimed_devices,
            "firmwares":       firmware_releases,
            "api_tokens":      api_tokens,
            "new_key":         new_key,
            "carrier_boards":  carrier_boards,
            "application_groups": application_groups,
            "firmware_names": firmware_names,
            "firmware_versions_by_name": firmware_versions_by_name,
            "staging_rows": staging_rows,
            "scope_options":   scope_options,
            "fleet_nodes":     fleet_nodes,
            "unclaimed_devices": unclaimed_rows,
            "allowed_emails":  allowed_emails,
            "allowed_domains": allowed_domains,
            "admin_api_tokens": admin_api_tokens,
            "admin_teams": admin_teams,
            "admin_users": admin_users,
        },
    )


# Keep /admin as a redirect for backwards compatibility with bookmarks.
@app.get("/admin", include_in_schema=False)
async def admin_redirect():
    return RedirectResponse(url="/dashboard")


# =============================================================================
# Access Management (Admin-only)
# =============================================================================

@app.post("/admin/access/emails/add")
def access_add_email(
    request: Request,
    email:   str = Form(...),
    note:    str = Form(""),
    db:      Session = Depends(get_db),
):
    current_user = get_current_user_from_db(request, db)
    if current_user.role != UserRole.Admin:
        raise HTTPException(status_code=403, detail="Admin only.")
    email = email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address.")
    if db.query(AllowedEmail).filter(AllowedEmail.email == email).first():
        raise HTTPException(status_code=409, detail="Email already in allowlist.")
    db.add(AllowedEmail(email=email, note=note.strip() or None))
    db.commit()
    return RedirectResponse(url="/dashboard?tab=access", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/access/emails/delete/{entry_id}")
def access_delete_email(
    entry_id: int,
    request:  Request,
    db:       Session = Depends(get_db),
):
    current_user = get_current_user_from_db(request, db)
    if current_user.role != UserRole.Admin:
        raise HTTPException(status_code=403, detail="Admin only.")
    entry = db.query(AllowedEmail).filter(AllowedEmail.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found.")
    # Guard: prevent removing your own entry — would lock yourself out.
    if entry.email == current_user.email:
        raise HTTPException(status_code=400, detail="Cannot remove your own email from the allowlist.")
    db.delete(entry)
    db.commit()
    return RedirectResponse(url="/dashboard?tab=access", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/access/domains/add")
def access_add_domain(
    request: Request,
    domain:  str = Form(...),
    note:    str = Form(""),
    db:      Session = Depends(get_db),
):
    current_user = get_current_user_from_db(request, db)
    if current_user.role != UserRole.Admin:
        raise HTTPException(status_code=403, detail="Admin only.")
    domain = domain.strip().lower().lstrip("@")
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain (e.g. borealtek.ca).")
    if db.query(AllowedDomain).filter(AllowedDomain.domain == domain).first():
        raise HTTPException(status_code=409, detail="Domain already in allowlist.")
    db.add(AllowedDomain(domain=domain, note=note.strip() or None))
    db.commit()
    return RedirectResponse(url="/dashboard?tab=access", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/access/domains/delete/{entry_id}")
def access_delete_domain(
    entry_id: int,
    request:  Request,
    db:       Session = Depends(get_db),
):
    current_user = get_current_user_from_db(request, db)
    if current_user.role != UserRole.Admin:
        raise HTTPException(status_code=403, detail="Admin only.")
    entry = db.query(AllowedDomain).filter(AllowedDomain.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found.")
    db.delete(entry)
    db.commit()
    return RedirectResponse(url="/dashboard?tab=access", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/teams/add")
def admin_add_team(
    team_name: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user),
):
    _ = current_user
    name = team_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Team name is required.")
    if db.query(Team).filter(Team.name == name).first():
        raise HTTPException(status_code=409, detail="Team already exists.")
    db.add(Team(name=name))
    db.commit()
    return RedirectResponse(url="/dashboard?tab=admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/teams/assign")
def admin_assign_team(
    email: str = Form(...),
    team_name: Optional[str] = Form(None),
    team_id: Optional[int] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user),
):
    _ = current_user
    normalized_email = email.strip().lower()
    if not normalized_email or "@" not in normalized_email:
        raise HTTPException(status_code=400, detail="Invalid email address.")

    user = db.query(User).filter(User.email == normalized_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    team = None
    if team_id is not None:
        team = db.query(Team).filter(Team.id == team_id).first()
    elif team_name:
        team = db.query(Team).filter(Team.name == team_name.strip()).first()

    if not team:
        raise HTTPException(status_code=404, detail="Team not found.")

    if team not in user.teams:
        user.teams.append(team)
        db.commit()

    return RedirectResponse(url="/dashboard?tab=admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/teams/members/remove")
def admin_remove_user_from_team(
    team_id: int = Form(...),
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user),
):
    _ = current_user
    team = db.query(Team).filter(Team.id == team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if team in user.teams:
        user.teams.remove(team)
        db.commit()

    return RedirectResponse(url="/dashboard?tab=admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/teams/delete/{team_id}")
def admin_delete_team(
    team_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user),
):
    _ = current_user
    team = db.query(Team).filter(Team.id == team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found.")

    db.delete(team)
    db.commit()
    return RedirectResponse(url="/dashboard?tab=admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/hardware/add")
def admin_add_hardware_profile(
    name: str = Form(...),
    description: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user),
):
    _ = current_user
    normalized_name = name.strip()
    normalized_description = (description or "").strip() or None

    if not normalized_name:
        raise HTTPException(status_code=400, detail="Carrier board name is required.")

    if db.query(CarrierBoard).filter(CarrierBoard.name == normalized_name).first():
        raise HTTPException(status_code=409, detail="Carrier board already exists.")

    board_cols = db.execute(text("PRAGMA table_info(carrier_boards)")).fetchall()
    tags_is_required = any((row[1] == "tags" and int(row[3]) == 1) for row in board_cols)
    if tags_is_required:
        db.execute(
            text("INSERT INTO carrier_boards (name, description, tags) VALUES (:name, :description, :tags)"),
            {
                "name": normalized_name,
                "description": normalized_description,
                "tags": "[]",
            },
        )
    else:
        db.add(CarrierBoard(name=normalized_name, description=normalized_description))
    db.commit()
    return RedirectResponse(url="/dashboard?top=admin&sub=hardware", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/hardware/delete/{board_id}")
def admin_delete_hardware_profile(
    board_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user),
):
    _ = current_user
    board = db.query(CarrierBoard).filter(CarrierBoard.id == board_id).first()
    if not board:
        raise HTTPException(status_code=404, detail="Carrier board not found.")

    if board.name == DEFAULT_CARRIER_BOARD_NAME:
        raise HTTPException(status_code=400, detail="The default Breadboard profile cannot be deleted.")

    in_use_by_release = db.query(FirmwareRelease.id).filter(FirmwareRelease.carrier_board_id == board_id).first()
    in_use_by_device = db.query(Device.id).filter(Device.carrier_board_id == board_id).first()
    if in_use_by_release or in_use_by_device:
        raise HTTPException(status_code=400, detail="Carrier board is in use by devices or firmware releases.")

    db.delete(board)
    db.commit()
    return RedirectResponse(url="/dashboard?top=admin&sub=hardware", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# API Key Management (OAuth-protected)
# =============================================================================

@app.post("/api/tokens/generate")
@app.post("/admin/tokens/generate")
@app.post("/admin/generate-key")
def generate_key(
    request: Request,
    label:   Optional[str] = Form(None),
    db:      Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate a cryptographically secure API key for the authenticated user.
    Only the SHA-256 hash is persisted; the raw key is surfaced once via a
    session flash and then discarded.  Uses the PRG pattern (POST → redirect
    → GET) to prevent accidental duplicate submissions.
    """
    raw_key = secrets.token_urlsafe(32)

    if label is not None and label != "" and not label.strip():
        raise HTTPException(status_code=400, detail="Token note cannot be whitespace only.")
    if label is not None and len(label) > 120:
        raise HTTPException(status_code=400, detail="Token note cannot exceed 120 characters.")

    token_label = (label or "").strip() or f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC"

    db.add(APIKey(
        key_hash=hash_api_key(raw_key),
        key_suffix=raw_key[-8:],
        label=token_label,
        owner_id=current_user.id,
        user_id=current_user.id,
    ))
    db.commit()

    request.session["new_key_flash"] = raw_key
    return RedirectResponse(url="/dashboard?tab=tokens", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/api/tokens/revoke/{key_id}")
@app.post("/admin/tokens/revoke/{key_id}")
@app.post("/admin/delete-key/{key_id}")
def delete_key(
    key_id:  int,
    request: Request,
    db:      Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke an API key. Users can revoke own keys; Admin can revoke any key."""
    _ = request

    key = db.query(APIKey).filter(
        APIKey.id == key_id,
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found.")

    if current_user.role != UserRole.Admin and key.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only revoke your own tokens.")

    db.delete(key)
    db.commit()
    return RedirectResponse(url="/dashboard?tab=tokens", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Machine-to-Machine: Firmware Upload (API Key protected)
# =============================================================================

@app.post("/admin/upload-firmware", status_code=201)
@app.post("/api/upload-firmware", status_code=201)
def upload_firmware_m2m(
    request:           Request,
    file:              UploadFile,
    firmware_name:     str = Form(...),
    firmware_version:  Optional[str] = Form(None),
    version:           Optional[str] = Form(None),
    version_string:    Optional[str] = Form(None),
    compute_module:    str = Form(...),
    carrier_board_id:  int = Form(...),
    scope:             str = Form(...),
    db:                Session = Depends(get_db),
    admin_actor:       User = Depends(require_admin_actor),
):
    """
    Firmware upload endpoint supporting:
    - M2M CI/CD uploads via X-Admin-Key header
    - Web dashboard uploads via authenticated session

    Binds binaries to a CarrierBoard, preventing cross-profile deploys.
    """
    _ = request
    uploader_email = admin_actor.email

    if not file.filename or not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin firmware files are accepted.")

    scope_slug = _scope_slug(scope)
    if not scope_slug:
        raise HTTPException(status_code=400, detail="Missing scope.")

    carrier_board = db.query(CarrierBoard).filter(CarrierBoard.id == carrier_board_id).first()
    if not carrier_board:
        raise HTTPException(status_code=404, detail=f"CarrierBoard id={carrier_board_id} not found.")

    firmware_name_clean = _sanitize_field(firmware_name)
    if not firmware_name_clean:
        raise HTTPException(status_code=400, detail="Invalid firmware name.")

    raw_version = firmware_version or version_string or version
    if not raw_version:
        raise HTTPException(status_code=400, detail="Missing firmware_version.")

    compute_module_clean = (compute_module or "").strip()
    if not compute_module_clean:
        raise HTTPException(status_code=400, detail="Missing compute_module.")

    version_clean = _sanitize_field(raw_version, allow_dots=True)
    compute_module_slug = _sanitize_field(compute_module_clean)
    firmware_name_slug = _sanitize_field(firmware_name_clean)
    carrier_board_slug  = _sanitize_field(carrier_board.name)
    if not version_clean:
        raise HTTPException(status_code=400, detail="Invalid version string.")
    if not compute_module_slug:
        raise HTTPException(status_code=400, detail="Invalid compute_module.")

    existing_release = db.query(FirmwareRelease.id).filter(
        FirmwareRelease.firmware_name == firmware_name_clean,
        FirmwareRelease.firmware_version == version_clean,
        FirmwareRelease.compute_module == compute_module_clean,
        FirmwareRelease.carrier_board_id == carrier_board_id,
    ).first()
    if existing_release:
        raise HTTPException(status_code=409, detail="Firmware target already exists. Bump FIRMWARE_VERSION.")

    filename  = f"{carrier_board_slug}_{compute_module_slug}_{firmware_name_slug}_{version_clean}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    if not os.path.realpath(file_path).startswith(os.path.realpath(FIRMWARE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid path construction.")

    content = file.file.read()
    with open(file_path, "wb") as buf:
        buf.write(content)

    release = FirmwareRelease(
        firmware_name=firmware_name_clean,
        firmware_version=version_clean,
        file_path=file_path,
        compute_module=compute_module_clean,
        carrier_board_id=carrier_board_id,
    )
    db.add(release)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Firmware target already exists. Bump FIRMWARE_VERSION.")
    db.refresh(release)

    return JSONResponse(status_code=201, content={
        "message":             "Firmware release created.",
        "firmware_release_id": release.id,
        "firmware_name":       release.firmware_name,
        "firmware_version":    release.firmware_version,
        "carrier_board":       carrier_board.name,
        "scope":               scope_slug,
        "filename":            filename,
        "uploaded_by":         uploader_email,
    })


# =============================================================================
# Web Portal: Firmware Upload (OAuth-protected)
# =============================================================================

@app.post("/admin/upload", status_code=201)
def upload_firmware_web(
    request:           Request,
    file:              UploadFile,
    firmware_name:     str = Form(...),
    firmware_version:  Optional[str] = Form(None),
    version_string:    Optional[str] = Form(None),
    version:           Optional[str] = Form(None),
    compute_module:    str = Form(...),
    carrier_board_id:  int = Form(...),
    db:                Session = Depends(get_db),
):
    """
    Upload a firmware binary and rigidly bind it to a CarrierBoard.
    This hard constraint prevents a firmware build compiled for one hardware
    variant from ever being dispatched to a device with a different profile.
    """
    session_user = request.session.get("user")
    if not session_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    if not file.filename or not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin firmware files are accepted.")

    # Validate the target profile exists before writing anything to disk.
    carrier_board = db.query(CarrierBoard).filter(CarrierBoard.id == carrier_board_id).first()
    if not carrier_board:
        raise HTTPException(status_code=404, detail=f"CarrierBoard id={carrier_board_id} not found.")

    firmware_name_clean = _sanitize_field(firmware_name)
    if not firmware_name_clean:
        raise HTTPException(status_code=400, detail="Invalid firmware name.")

    raw_version = firmware_version or version_string or version
    if not raw_version:
        raise HTTPException(status_code=400, detail="Missing firmware_version.")

    compute_module_clean = (compute_module or "").strip()
    if not compute_module_clean:
        raise HTTPException(status_code=400, detail="Missing compute_module.")

    version_clean = _sanitize_field(raw_version, allow_dots=True)
    compute_module_slug = _sanitize_field(compute_module_clean)
    firmware_name_slug = _sanitize_field(firmware_name_clean)
    carrier_board_slug  = _sanitize_field(carrier_board.name)
    if not version_clean:
        raise HTTPException(status_code=400, detail="Invalid version string.")
    if not compute_module_slug:
        raise HTTPException(status_code=400, detail="Invalid compute_module.")

    existing_release = db.query(FirmwareRelease.id).filter(
        FirmwareRelease.firmware_name == firmware_name_clean,
        FirmwareRelease.firmware_version == version_clean,
        FirmwareRelease.compute_module == compute_module_clean,
        FirmwareRelease.carrier_board_id == carrier_board_id,
    ).first()
    if existing_release:
        raise HTTPException(status_code=409, detail="Firmware target already exists. Bump FIRMWARE_VERSION.")

    filename  = f"{carrier_board_slug}_{compute_module_slug}_{firmware_name_slug}_{version_clean}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    # Path-traversal guard.
    if not os.path.realpath(file_path).startswith(os.path.realpath(FIRMWARE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid path construction.")

    content = file.file.read()
    with open(file_path, "wb") as buf:
        buf.write(content)

    release = FirmwareRelease(
        firmware_name=firmware_name_clean,
        firmware_version=version_clean,
        file_path=file_path,
        compute_module=compute_module_clean,
        carrier_board_id=carrier_board_id,
    )
    db.add(release)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Firmware target already exists. Bump FIRMWARE_VERSION.")

    return JSONResponse(status_code=201, content={"message": "Firmware upload successful."})


# =============================================================================
# ESP32 OTA Check-Update (Device Secret Auth)
# =============================================================================

@app.post("/check-update")
def check_update(
    x_device_mac:       Optional[str] = Header(default=None),
    x_device_secret:    Optional[str] = Header(default=None),
    x_firmware_name:    Optional[str] = Header(default=None),
    x_firmware_version: Optional[str] = Header(default=None),
    x_device_battery:   Optional[str] = Header(default=None),
    x_compute_module:   Optional[str] = Header(default=None),
    db:                 Session        = Depends(get_db),
):
    if not all([x_device_mac, x_device_secret, x_firmware_version]):
        return JSONResponse(status_code=400, content={"error": "Missing required headers."})

    # ── Step 1: Device lookup ──────────────────────────────────────────────
    device = db.query(Device).filter(Device.mac_address == x_device_mac).first()

    if not device:
        # Unknown device — register so the dashboard surfaces it for claiming.
        db.add(Device(
            mac_address=x_device_mac,
            secret="pending_claim",
            device_class="unknown",
            version=x_firmware_version,
            compute_module=x_compute_module,
            claimed=False,
            last_checkin=datetime.utcnow(),
        ))
        db.commit()
        return JSONResponse(status_code=202, content={
            "update": False, "message": "Device registered and awaiting claiming."
        })

    if not device.claimed:
        return JSONResponse(status_code=202, content={
            "update": False, "message": "Device not yet claimed by an owner."
        })

    # ── Step 2: Authenticate ───────────────────────────────────────────────
    if not secrets.compare_digest(device.secret, x_device_secret):
        raise HTTPException(status_code=403, detail="Forbidden: Secret mismatch.")

    # ── Step 3: Update telemetry ───────────────────────────────────────────
    device.last_checkin = datetime.utcnow()
    device.version = x_firmware_version
    if x_compute_module:
        device.compute_module = x_compute_module
    if x_device_battery is not None:
        try:
            device.battery = int(x_device_battery)
        except ValueError:
            pass
    db.commit()

    # ── Step 4: Cascading Resolution ──────────────────────────────────────
    target_firmware_name = ""
    target_firmware_version = ""
    if device.application_group:
        target_firmware_name = _normalize_firmware_name(device.application_group.target_firmware_name)
        target_firmware_version = _normalize_firmware_version(device.application_group.target_firmware_version)
        if device.application_group.target_release:
            if not target_firmware_name:
                target_firmware_name = _normalize_firmware_name(device.application_group.target_release.firmware_name)
            if not target_firmware_version:
                target_firmware_version = _normalize_firmware_version(device.application_group.target_release.firmware_version)

    if not target_firmware_name:
        target_firmware_name = _normalize_firmware_name(x_firmware_name)

    if not target_firmware_name:
        return Response(status_code=204)

    if not device.compute_module or device.carrier_board_id is None:
        return Response(status_code=204)

    # Meticulous matching against the socketed hardware combination
    release_query = db.query(FirmwareRelease).filter(
        FirmwareRelease.firmware_name == target_firmware_name,
        FirmwareRelease.compute_module == device.compute_module,
        FirmwareRelease.carrier_board_id == device.carrier_board_id,
    )
    if target_firmware_version:
        release_query = release_query.filter(FirmwareRelease.firmware_version == target_firmware_version)
    resolved_release = release_query.order_by(FirmwareRelease.id.desc()).first()

    # ── Step 5: Deployment decision ───────────────────────────────────────
    if resolved_release is None:
        return Response(status_code=204)

    if not is_newer_version(resolved_release.firmware_version, x_firmware_version):
        return Response(status_code=204)

    if not os.path.exists(resolved_release.file_path):
        print(f"WARNING: FirmwareRelease id={resolved_release.id} file missing: {resolved_release.file_path}")
        return Response(status_code=204)

    device.last_ota_status = f"update_dispatched:{resolved_release.firmware_name}:{resolved_release.firmware_version}"
    db.commit()

    return FileResponse(
        resolved_release.file_path,
        media_type="application/octet-stream",
        filename=os.path.basename(resolved_release.file_path),
        headers={"X-Firmware-Version": resolved_release.firmware_version},
    )


class ClaimDevicePayload(BaseModel):
    scope_type: ScopeType
    target_id: int

@app.post("/devices/{mac_address}/claim")
def claim_device(
    request: Request,
    mac_address: str,
    payload: ClaimDevicePayload,
    db: Session = Depends(get_db)
):
    user = get_current_user_from_db(request, db)
    allowed_scopes = get_current_user_scopes(user=user)
    
    if user.role.value != "Admin" and (payload.scope_type, payload.target_id) not in allowed_scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="You do not have permission to claim hardware into this scope."
        )
        
    device = db.query(Device).filter(Device.mac_address == mac_address).first()
    
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")
        
    if device.claimed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device is already claimed.")
        
    device.claimed = True
    device.scope_type = payload.scope_type
    device.scope_id = payload.target_id
    
    # Generate a real strict secret on claim
    device.secret = secrets.token_urlsafe(32)
    
    db.commit()
    db.refresh(device)
    
    return {"message": "Device claimed.", "mac_address": device.mac_address, "new_secret": device.secret}


@app.post("/api/claim")
def claim_device_from_form(
    request: Request,
    mac: str = Form(...),
    scope: str = Form(...),
    labels: str = Form(""),
    carrier_board_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user_from_db(request, db)

    device = db.query(Device).filter(Device.mac_address == mac).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")
    if device.claimed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device is already claimed.")

    target_scope_type, target_scope_id, _ = _resolve_scope_selection(scope, user, db)
    if not _has_scope_access(user, target_scope_type, target_scope_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to claim hardware into this scope.",
        )

    parsed_board_id = _parse_optional_int(carrier_board_id, "carrier_board_id")
    if parsed_board_id is not None:
        if not db.query(CarrierBoard).filter(CarrierBoard.id == parsed_board_id).first():
            raise HTTPException(status_code=404, detail="Carrier board not found.")

    device.claimed = True
    device.scope_type = target_scope_type
    device.scope_id = target_scope_id
    device.carrier_board_id = parsed_board_id
    device.secret = secrets.token_urlsafe(32)
    _upsert_labels_for_device(device, labels, db)

    db.commit()
    return RedirectResponse(url="/dashboard?top=devices&sub=onboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/api/fleet/devices/{mac}/update")
def update_fleet_device(
    mac: str,
    request: Request,
    scope: str = Form(...),
    labels: str = Form(""),
    carrier_board_id: Optional[str] = Form(None),
    firmware_override_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ = request
    device = db.query(Device).filter(Device.mac_address == mac).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
    if not device.claimed:
        raise HTTPException(status_code=400, detail="Cannot manage an unclaimed device.")

    if not _can_manage_device(current_user, device):
        raise HTTPException(status_code=403, detail="You do not have permission to manage this device.")

    target_scope_type, target_scope_id, _ = _resolve_scope_selection(scope, current_user, db)
    if not _has_scope_access(current_user, target_scope_type, target_scope_id):
        raise HTTPException(status_code=403, detail="You do not have permission to assign this scope.")

    parsed_board_id = _parse_optional_int(carrier_board_id, "carrier_board_id")
    parsed_override_id = _parse_optional_int(firmware_override_id, "firmware_override_id")

    if parsed_board_id is not None:
        if not db.query(CarrierBoard).filter(CarrierBoard.id == parsed_board_id).first():
            raise HTTPException(status_code=404, detail="Carrier board not found.")

    if parsed_override_id is not None:
        release = db.query(FirmwareRelease).filter(FirmwareRelease.id == parsed_override_id).first()
        if not release:
            raise HTTPException(status_code=404, detail="Firmware release not found.")
        # Ensure the override firmware matches the device's carrier board.
        effective_board_id = parsed_board_id if parsed_board_id is not None else device.carrier_board_id
        if effective_board_id is not None and release.carrier_board_id != effective_board_id:
            raise HTTPException(status_code=400, detail="Firmware carrier board mismatch for device.")

    device.scope_type = target_scope_type
    device.scope_id = target_scope_id
    device.carrier_board_id = parsed_board_id
    device.firmware_override_id = parsed_override_id
    _upsert_labels_for_device(device, labels, db)

    db.commit()
    return RedirectResponse(url="/dashboard?top=devices&sub=fleet", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/api/groups/{group_id}/readiness")
def get_group_readiness(
    group_id: int,
    firmware_name: str,
    firmware_version: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    group = db.query(ApplicationGroup).filter(ApplicationGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Application group not found.")

    if current_user.role != UserRole.Admin and group.team not in current_user.teams:
        raise HTTPException(status_code=403, detail="You do not have permission to inspect this group.")

    return _evaluate_group_readiness(group, firmware_name, firmware_version, db)


@app.post("/api/deploy")
def deploy_firmware_target_to_group(
    group_id: int = Form(...),
    firmware_name: str = Form(...),
    firmware_version: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user),
):
    _ = current_user
    group = db.query(ApplicationGroup).filter(ApplicationGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Application group not found.")

    normalized_name = _normalize_firmware_name(firmware_name)
    normalized_version = _normalize_firmware_version(firmware_version)
    if not normalized_name or not normalized_version:
        raise HTTPException(status_code=400, detail="firmware_name and firmware_version are required.")

    readiness = _evaluate_group_readiness(group, normalized_name, normalized_version, db)
    if not readiness["ready"]:
        raise HTTPException(status_code=400, detail="Firmware target is not ready for this group.")

    group.target_firmware_name = normalized_name
    group.target_firmware_version = normalized_version

    # Legacy bridge for views still keyed by target_release_id.
    newest_matching_release = db.query(FirmwareRelease).filter(
        FirmwareRelease.firmware_name == normalized_name,
        FirmwareRelease.firmware_version == normalized_version,
    ).order_by(FirmwareRelease.id.desc()).first()
    group.target_release_id = newest_matching_release.id if newest_matching_release else None

    db.commit()
    return {
        "message": "Firmware target deployed to group.",
        "group_id": group.id,
        "firmware_name": normalized_name,
        "firmware_version": normalized_version,
    }


@app.post("/api/fleet/unclaim/{mac}")
def unclaim_device(
    mac: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user),
):
    _ = current_user
    device = db.query(Device).filter(Device.mac_address == mac).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    device.claimed = False
    device.scope_type = None
    device.scope_id = None
    device.application_group_id = None
    device.firmware_override_id = None
    device.secret = "pending_claim"
    db.commit()
    return RedirectResponse(url="/dashboard?top=devices&sub=fleet", status_code=status.HTTP_303_SEE_OTHER)
