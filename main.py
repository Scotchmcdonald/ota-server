import hashlib
import os
import re
import secrets
from datetime import datetime
from typing import Optional

from authlib.integrations.starlette_client import OAuth
from fastapi import Body, Depends, FastAPI, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from packaging.version import parse as parse_version
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine, event, text
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

# =============================================================================
# App & Session Middleware
# =============================================================================
app = FastAPI(title="ESP32 Fleet OTA Server")

# SESSION_SECRET_KEY MUST be a fixed, strong random value set as an env var in
# production. If left to the default (generated at startup), every server
# restart will invalidate all active sessions.
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", secrets.token_urlsafe(32))
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

# =============================================================================
# Directory Configuration
# =============================================================================
DATA_DIR = "/app/data"
FIRMWARE_DIR = os.path.join(DATA_DIR, "firmware")
os.makedirs(FIRMWARE_DIR, exist_ok=True)

# =============================================================================
# Google OAuth Configuration
# =============================================================================
# STEP 1 ── Go to https://console.cloud.google.com/apis/credentials
# STEP 2 ── Create an "OAuth 2.0 Client ID" → Application type: Web application
# STEP 3 ── Add an Authorized Redirect URI:
#              http://<your-server-hostname>/auth/callback
# STEP 4 ── Copy the Client ID and Client Secret and set them as env vars, or
#            paste them directly below (not recommended for production):
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID",     "PASTE_YOUR_GOOGLE_CLIENT_ID_HERE")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "PASTE_YOUR_GOOGLE_CLIENT_SECRET_HERE")

# Admin email whitelist ── only addresses in this set may access the dashboard.
# Set the ADMIN_EMAILS env var as a comma-separated list, e.g.:
#   ADMIN_EMAILS=you@gmail.com,colleague@company.com
ADMIN_EMAILS: set[str] = {
    e.strip()
    for e in os.getenv("ADMIN_EMAILS", "admin@example.com").split(",")
    if e.strip()
}

oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    # Google's OIDC discovery document — Authlib fetches this at runtime to
    # resolve the authorization, token, and userinfo endpoint URLs.
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

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
Base = declarative_base()

# =============================================================================
# Models
# =============================================================================

class AdminUser(Base):
    """Represents a human admin authenticated via Google OAuth."""
    __tablename__ = "admin_users"
    id         = Column(Integer, primary_key=True, index=True)
    email      = Column(String, unique=True, nullable=False, index=True)
    name       = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # One admin can own many API keys; deleting the admin cascades to keys.
    api_keys   = relationship("APIKey", back_populates="owner", cascade="all, delete-orphan")


class APIKey(Base):
    """
    Stores a SHA-256 hash of a machine-to-machine API key.
    The raw key is shown to the admin exactly once at generation time and is
    never stored in plain text.
    """
    __tablename__ = "api_keys"
    id         = Column(Integer, primary_key=True, index=True)
    key_hash   = Column(String, nullable=False, index=True)  # SHA-256 of the raw token
    label      = Column(String, nullable=True)               # Human-readable creation note
    owner_id   = Column(Integer, ForeignKey("admin_users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    owner      = relationship("AdminUser", back_populates="api_keys")


class Device(Base):
    """ESP32 device that checks in for OTA updates."""
    __tablename__ = "devices"
    mac_address     = Column(String, primary_key=True, index=True)
    secret          = Column(String, nullable=False)
    device_class    = Column(String, nullable=False)
    current_version = Column(String)
    track           = Column(String, default="prod")     # 'prod' | 'dev'
    status          = Column(String, default="pending")  # 'pending' | 'approved'
    last_checkin    = Column(DateTime, default=datetime.utcnow)
    last_ota_status = Column(String)
    battery_level   = Column(String, nullable=True)


class Firmware(Base):
    """A compiled .bin firmware artifact uploaded to the server."""
    __tablename__ = "firmware"
    id               = Column(Integer, primary_key=True, index=True)
    device_class     = Column(String, nullable=False)
    version          = Column(String, nullable=False)
    track            = Column(String, default="prod")
    file_path        = Column(String, nullable=False)
    upload_timestamp = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

# Idempotent column migrations — silently skipped if the column already exists.
_MIGRATIONS = [
    "ALTER TABLE devices ADD COLUMN track VARCHAR DEFAULT 'prod'",
    "ALTER TABLE devices ADD COLUMN status VARCHAR DEFAULT 'pending'",
    "ALTER TABLE devices ADD COLUMN last_ota_status VARCHAR",
    "ALTER TABLE devices ADD COLUMN battery_level VARCHAR",
]
with engine.connect() as _conn:
    for _stmt in _MIGRATIONS:
        try:
            _conn.execute(text(_stmt))
            _conn.commit()
        except Exception:
            pass  # Column already exists — safe to ignore.

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


def hash_api_key(raw_key: str) -> str:
    """One-way SHA-256 hash of a raw API key token for safe database storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


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


# =============================================================================
# Auth Dependencies
# =============================================================================

def get_current_user(request: Request) -> dict:
    """
    FastAPI dependency for OAuth-protected endpoints.
    Raises 401 if the session has no authenticated user, or 403 if the
    authenticated email is not in the ADMIN_EMAILS whitelist.
    Returns the session user dict on success.
    """
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please visit /login.",
        )
    if user.get("email") not in ADMIN_EMAILS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {user.get('email')} is not an authorized admin.",
        )
    return user


def verify_api_key(
    x_admin_key: str = Header(..., description="Machine API key — set as X-Admin-Key header"),
    db: Session = Depends(get_db),
) -> "APIKey":
    """
    FastAPI dependency for machine-to-machine endpoints (e.g., VS Code upload).
    Hashes the incoming X-Admin-Key header and looks it up in the database.
    Returns the APIKey ORM object on success; raises 401 on failure.

    Example curl usage:
        curl -X POST https://<server>/admin/upload-firmware \\
             -H "X-Admin-Key: <raw_key>" \\
             -F "file=@firmware.bin" \\
             -F "device_class=sensor_node_v1" \\
             -F "version=1.2.0"
    """
    key_hash = hash_api_key(x_admin_key)
    api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return api_key


# =============================================================================
# Request Schemas
# =============================================================================

class ApproveDeviceRequest(BaseModel):
    track: str = "prod"


# =============================================================================
# Google OAuth Routes
# =============================================================================

@app.get("/login", include_in_schema=False)
async def login(request: Request):
    """Redirect the browser to Google's OAuth 2.0 consent screen."""
    redirect_uri = request.url_for("auth_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth", name="auth_callback", include_in_schema=False)
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    """
    Google OAuth callback handler.
    Exchanges the authorization code for tokens, retrieves the user profile,
    enforces the ADMIN_EMAILS whitelist, upserts the AdminUser record, and
    stores minimal user info in the encrypted session cookie.
    """
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth authorization failed. Please try again.",
        )

    user_info = token.get("userinfo")
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve user info from Google.",
        )

    email = user_info.get("email", "").strip().lower()

    # Enforce the whitelist immediately after receiving identity from Google.
    if email not in ADMIN_EMAILS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {email} is not an authorized admin.",
        )

    # Upsert the AdminUser record so API keys have a valid FK target.
    admin_user = db.query(AdminUser).filter(AdminUser.email == email).first()
    if not admin_user:
        admin_user = AdminUser(email=email, name=user_info.get("name", ""))
        db.add(admin_user)
        db.commit()

    # Store only the minimal fields needed by the UI in the session cookie.
    request.session["user"] = {"email": email, "name": user_info.get("name", "")}
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
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """
    Main admin dashboard. Protected by Google OAuth + ADMIN_EMAILS whitelist.
    Handles the session check inline so unauthenticated browsers get a redirect
    to /login rather than a JSON 401.
    """
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login")
    if user.get("email") not in ADMIN_EMAILS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    devices   = db.query(Device).all()
    firmwares = db.query(Firmware).order_by(Firmware.id.desc()).all()

    # Fetch the API keys owned by the current admin (IDs + labels only; no raw keys).
    admin_user = db.query(AdminUser).filter(AdminUser.email == user["email"]).first()
    api_keys   = admin_user.api_keys if admin_user else []

    # One-time flash: pop the newly generated raw key from the session and pass
    # it to the template; it will not be available on subsequent page loads.
    new_key = request.session.pop("new_key_flash", None)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user":      user,
            "devices":   devices,
            "firmwares": firmwares,
            "api_keys":  api_keys,
            "new_key":   new_key,  # Raw key shown exactly once after generation.
        },
    )


# Keep /admin as a redirect for backwards compatibility with bookmarks.
@app.get("/admin", include_in_schema=False)
async def admin_redirect():
    return RedirectResponse(url="/dashboard")


# =============================================================================
# API Key Management (OAuth-protected)
# =============================================================================

@app.post("/admin/generate-key")
async def generate_key(
    request: Request,
    db:      Session = Depends(get_db),
    user:    dict    = Depends(get_current_user),
):
    """
    Generate a cryptographically secure API key for the authenticated admin.
    Only the SHA-256 hash is persisted; the raw key is surfaced once via a
    session flash and then discarded.  Uses the PRG pattern (POST → redirect
    → GET) to prevent accidental duplicate submissions.
    """
    email = user["email"]
    admin_user = db.query(AdminUser).filter(AdminUser.email == email).first()
    if not admin_user:
        # Guard: create the record if somehow it was never inserted.
        admin_user = AdminUser(email=email, name=user.get("name", ""))
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

    # secrets.token_urlsafe(32) produces 256 bits of entropy — overkill-proof.
    raw_key = secrets.token_urlsafe(32)

    db.add(APIKey(
        key_hash=hash_api_key(raw_key),
        label=f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
        owner_id=admin_user.id,
    ))
    db.commit()

    # Flash the raw key via the session so it survives the redirect exactly once.
    request.session["new_key_flash"] = raw_key
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/delete-key/{key_id}")
async def delete_key(
    key_id:  int,
    request: Request,
    db:      Session = Depends(get_db),
    user:    dict    = Depends(get_current_user),
):
    """Revoke an API key. The key must belong to the authenticated admin."""
    admin_user = db.query(AdminUser).filter(AdminUser.email == user["email"]).first()
    if not admin_user:
        raise HTTPException(status_code=404, detail="Admin user not found.")

    key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.owner_id == admin_user.id,  # Ownership check prevents IDOR.
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found.")

    db.delete(key)
    db.commit()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Machine-to-Machine: Firmware Upload (API Key protected)
# =============================================================================

@app.post("/admin/upload-firmware")
async def upload_firmware_m2m(
    file:         UploadFile,
    device_class: str     = Form(...),
    version:      str     = Form(...),
    track:        str     = Form("prod"),
    db:           Session = Depends(get_db),
    api_key:      APIKey  = Depends(verify_api_key),
):
    """
    Machine-to-machine firmware upload endpoint authenticated via X-Admin-Key.
    Intended for VS Code tasks, CI/CD pipelines, or any automated script —
    NOT the OAuth browser session.

    Example (VS Code task or shell script):
        curl -X POST http://<server>/admin/upload-firmware \\
             -H "X-Admin-Key: <raw_api_key>" \\
             -F "file=@build/firmware.bin" \\
             -F "device_class=sensor_node_v1" \\
             -F "version=1.2.0" \\
             -F "track=prod"
    """
    if not file.filename or not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin firmware files are accepted.")

    # Strict sanitization — reject any character that could enable path traversal.
    device_class = _sanitize_field(device_class)
    version      = _sanitize_field(version, allow_dots=True)
    track        = _sanitize_field(track)

    if not device_class or not version or not track:
        raise HTTPException(status_code=400, detail="Invalid characters in form fields.")

    filename  = f"{device_class}_{track}_{version}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    # Final path-traversal guard using realpath resolution.
    if not os.path.realpath(file_path).startswith(os.path.realpath(FIRMWARE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid path construction.")

    with open(file_path, "wb") as buf:
        buf.write(await file.read())

    db.add(Firmware(device_class=device_class, version=version, track=track, file_path=file_path))
    db.commit()

    return JSONResponse(status_code=200, content={
        "message":      "Firmware uploaded successfully.",
        "filename":     filename,
        "device_class": device_class,
        "version":      version,
        "track":        track,
        "uploaded_by":  api_key.owner.email if api_key.owner else "unknown",
    })


# =============================================================================
# Web Portal: Firmware Upload (OAuth-protected)
# =============================================================================

@app.post("/admin/upload")
async def upload_firmware_web(
    request:      Request,
    file:         UploadFile,
    device_class: str     = Form(...),
    version:      str     = Form(...),
    track:        str     = Form(...),
    db:           Session = Depends(get_db),
    user:         dict    = Depends(get_current_user),
):
    """Web portal firmware upload — same logic as the M2M endpoint but gated
    by the OAuth session and redirects back to /dashboard on success."""
    if not file.filename or not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin files are allowed.")

    device_class = _sanitize_field(device_class)
    version      = _sanitize_field(version, allow_dots=True)
    track        = _sanitize_field(track)

    if not device_class or not version or not track:
        raise HTTPException(status_code=400, detail="Invalid form data.")

    filename  = f"{device_class}_{track}_{version}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    if not os.path.realpath(file_path).startswith(os.path.realpath(FIRMWARE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid path construction.")

    with open(file_path, "wb") as buf:
        buf.write(await file.read())

    db.add(Firmware(device_class=device_class, version=version, track=track, file_path=file_path))
    db.commit()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Admin: Device Approval (OAuth-protected)
# =============================================================================

@app.post("/admin/devices/{mac_address}/approve")
def approve_device(
    mac_address: str,
    payload:     Optional[ApproveDeviceRequest] = Body(None),
    db:          Session = Depends(get_db),
    user:        dict    = Depends(get_current_user),
):
    """Approve a pending device and assign its release track."""
    mac_address = mac_address.strip()
    device = db.query(Device).filter(Device.mac_address == mac_address).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
    if device.status == "approved":
        return JSONResponse(status_code=200, content={"message": "Device is already approved."})

    device.status = "approved"
    device.track  = (payload.track if payload and payload.track in ("prod", "dev") else None) or device.track or "prod"
    db.commit()
    db.refresh(device)
    return JSONResponse(status_code=200, content={
        "message":     f"Device {mac_address} approved.",
        "mac_address": mac_address,
        "track":       device.track,
    })


# =============================================================================
# ESP32 OTA Check-Update (Device Secret Auth)
# =============================================================================

@app.post("/check-update")
def check_update(
    x_device_mac:       Optional[str] = Header(default=None),
    x_device_secret:    Optional[str] = Header(default=None),
    x_device_class:     Optional[str] = Header(default=None),
    x_firmware_version: Optional[str] = Header(default=None),
    x_device_battery:   Optional[str] = Header(default=None),
    db:                 Session        = Depends(get_db),
):
    """
    ESP32 OTA check-in endpoint.
    1. Validates required headers.
    2. Registers new devices (status=pending) or authenticates returning ones.
    3. Returns the latest firmware binary if a newer version is available;
       otherwise responds 204 No Content so the device skips the update.
    """
    if not all([x_device_mac, x_device_secret, x_device_class, x_firmware_version]):
        return JSONResponse(status_code=400, content={
            "error": "Missing required headers: X-Device-MAC, X-Device-SECRET, X-Device-Class, X-Firmware-Version."
        })

    x_device_mac       = x_device_mac.strip()
    x_device_class     = x_device_class.strip()
    x_firmware_version = x_firmware_version.strip()

    device = db.query(Device).filter(Device.mac_address == x_device_mac).first()

    if not device:
        db.add(Device(
            mac_address=x_device_mac,
            secret=x_device_secret,
            device_class=x_device_class,
            current_version=x_firmware_version,
            track="prod",
            status="pending",
            last_checkin=datetime.utcnow(),
            battery_level=x_device_battery,
        ))
        db.commit()
        return JSONResponse(status_code=202, content={
            "update": False, "message": "Device registered and pending admin approval."
        })

    # Use constant-time comparison to prevent timing oracle attacks.
    if not secrets.compare_digest(device.secret, x_device_secret):
        raise HTTPException(status_code=403, detail="Forbidden: Secret mismatch.")

    device.last_checkin     = datetime.utcnow()
    device.current_version  = x_firmware_version
    device.device_class     = x_device_class
    if x_device_battery is not None:
        device.battery_level = x_device_battery
    db.commit()

    if device.status == "pending":
        return JSONResponse(status_code=202, content={
            "update": False, "message": "Still pending admin approval."
        })

    latest_firmware = db.query(Firmware).filter(
        Firmware.device_class == device.device_class,
        Firmware.track        == device.track,
    ).order_by(Firmware.id.desc()).first()

    if latest_firmware and is_newer_version(latest_firmware.version, x_firmware_version):
        if os.path.exists(latest_firmware.file_path):
            return FileResponse(
                latest_firmware.file_path,
                media_type="application/octet-stream",
                filename=os.path.basename(latest_firmware.file_path),
            )
        print(f"WARNING: Firmware record exists but file is missing: {latest_firmware.file_path}")

    return Response(status_code=204)
