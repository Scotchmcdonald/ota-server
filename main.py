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
from starlette.exceptions import HTTPException as StarletteHTTPException
from packaging.version import parse as parse_version
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine, event
from starlette.middleware.sessions import SessionMiddleware
from models import Base, User, Team, APIKey, Device, Firmware, Label, UserRole, ScopeType, DeviceProfile, FirmwareRelease, ApplicationGroup, AllowedEmail, AllowedDomain
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

# =============================================================================
# Access Allowlist: Bootstrap from Env Var on First Run
# =============================================================================
def _seed_allowlist_from_env():
    """
    On startup, inject any emails from the ADMIN_EMAILS env var into the DB
    if they are not already present. This bootstraps the first deployment so
    the admin can log in and manage the list from the UI thereafter.
    """
    if not ADMIN_EMAILS:
        return
    db = SessionLocal()
    try:
        for email in ADMIN_EMAILS:
            if not db.query(AllowedEmail).filter(AllowedEmail.email == email).first():
                db.add(AllowedEmail(email=email, note="Seeded from ADMIN_EMAILS env var"))
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

# Seed DB allowlist from env var before the first request is handled.
_seed_allowlist_from_env()

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
        user = User(email=email, name=user_info.get("name", ""))
        db.add(user)
        db.commit()

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
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Main Flight Deck dashboard. Requires authentication."""
    session_user = request.session.get("user")
    if not session_user:
        return RedirectResponse(url="/login")

    user_info = get_current_user_from_db(request, db)

    if user_info.role == UserRole.Admin:
        devices          = db.query(Device).all()
        firmware_releases = db.query(FirmwareRelease).order_by(FirmwareRelease.id.desc()).all()
    else:
        team_ids = [t.id for t in user_info.teams]
        devices = db.query(Device).filter(
            (Device.scope_type == ScopeType.Team)     & Device.scope_id.in_(team_ids) |
            (Device.scope_type == ScopeType.Personal) & (Device.scope_id == user_info.id)
        ).all()
        firmware_releases = db.query(FirmwareRelease).order_by(FirmwareRelease.id.desc()).all()

    api_keys = user_info.api_keys
    new_key  = request.session.pop("new_key_flash", None)

    allowed_emails  = db.query(AllowedEmail).order_by(AllowedEmail.created_at).all()  if user_info.role == UserRole.Admin else []
    allowed_domains = db.query(AllowedDomain).order_by(AllowedDomain.created_at).all() if user_info.role == UserRole.Admin else []

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user":            session_user,
            "db_user":         user_info,
            "devices":         devices,
            "firmwares":       firmware_releases,
            "api_keys":        api_keys,
            "new_key":         new_key,
            "allowed_emails":  allowed_emails,
            "allowed_domains": allowed_domains,
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


# =============================================================================
# API Key Management (OAuth-protected)
# =============================================================================

@app.post("/admin/generate-key")
def generate_key(
    request: Request,
    db:      Session = Depends(get_db),
):
    """
    Generate a cryptographically secure API key for the authenticated user.
    Only the SHA-256 hash is persisted; the raw key is surfaced once via a
    session flash and then discarded.  Uses the PRG pattern (POST → redirect
    → GET) to prevent accidental duplicate submissions.
    """
    current_user = get_current_user_from_db(request, db)

    raw_key = secrets.token_urlsafe(32)

    db.add(APIKey(
        key_hash=hash_api_key(raw_key),
        label=f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
        owner_id=current_user.id,
    ))
    db.commit()

    request.session["new_key_flash"] = raw_key
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/delete-key/{key_id}")
def delete_key(
    key_id:  int,
    request: Request,
    db:      Session = Depends(get_db),
):
    """Revoke an API key. The key must belong to the authenticated user."""
    current_user = get_current_user_from_db(request, db)

    key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.owner_id == current_user.id,  # Ownership check prevents IDOR.
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found.")

    db.delete(key)
    db.commit()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Machine-to-Machine: Firmware Upload (API Key protected)
# =============================================================================

@app.post("/admin/upload-firmware", status_code=201)
def upload_firmware_m2m(
    file:              UploadFile,
    version:           str = Form(...),
    device_profile_id: int = Form(...),
    db:                Session = Depends(get_db),
    x_admin_key:       str = Header(...),
):
    """
    M2M firmware upload for CI/CD pipelines. Authenticated via X-Admin-Key header.
    Binds the binary to a DeviceProfile, preventing cross-profile deploys.
    """
    key_hash = hash_api_key(x_admin_key)
    api_key  = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key.")

    if not file.filename or not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin firmware files are accepted.")

    profile = db.query(DeviceProfile).filter(DeviceProfile.id == device_profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail=f"DeviceProfile id={device_profile_id} not found.")

    version_clean = _sanitize_field(version, allow_dots=True)
    profile_slug  = _sanitize_field(profile.name)
    if not version_clean:
        raise HTTPException(status_code=400, detail="Invalid version string.")

    filename  = f"{profile_slug}_{version_clean}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    if not os.path.realpath(file_path).startswith(os.path.realpath(FIRMWARE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid path construction.")

    content = file.file.read()
    with open(file_path, "wb") as buf:
        buf.write(content)

    release = FirmwareRelease(
        version=version_clean,
        file_path=file_path,
        device_profile_id=device_profile_id,
    )
    db.add(release)
    db.commit()
    db.refresh(release)

    return JSONResponse(status_code=201, content={
        "message":             "Firmware release created.",
        "firmware_release_id": release.id,
        "version":             release.version,
        "device_profile":      profile.name,
        "filename":            filename,
        "uploaded_by":         api_key.owner.email,
    })


# =============================================================================
# Web Portal: Firmware Upload (OAuth-protected)
# =============================================================================

@app.post("/admin/upload", status_code=201)
def upload_firmware_web(
    request:           Request,
    file:              UploadFile,
    version:           str = Form(...),
    device_profile_id: int = Form(...),
    db:                Session = Depends(get_db),
):
    """
    Upload a firmware binary and rigidly bind it to a DeviceProfile.
    This hard constraint prevents a firmware build compiled for one hardware
    variant from ever being dispatched to a device with a different profile.
    """
    session_user = request.session.get("user")
    if not session_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    if not file.filename or not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin firmware files are accepted.")

    # Validate the target profile exists before writing anything to disk.
    profile = db.query(DeviceProfile).filter(DeviceProfile.id == device_profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail=f"DeviceProfile id={device_profile_id} not found.")

    version_clean = _sanitize_field(version, allow_dots=True)
    profile_slug  = _sanitize_field(profile.name)
    if not version_clean:
        raise HTTPException(status_code=400, detail="Invalid version string.")

    filename  = f"{profile_slug}_{version_clean}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    # Path-traversal guard.
    if not os.path.realpath(file_path).startswith(os.path.realpath(FIRMWARE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid path construction.")

    content = file.file.read()
    with open(file_path, "wb") as buf:
        buf.write(content)

    release = FirmwareRelease(
        version=version_clean,
        file_path=file_path,
        device_profile_id=device_profile_id,
    )
    db.add(release)
    db.commit()
    db.refresh(release)

    return JSONResponse(status_code=201, content={
        "message": "Firmware release created.",
        "firmware_release_id": release.id,
        "version": release.version,
        "device_profile": profile.name,
        "filename": filename,
    })


# =============================================================================
# ESP32 OTA Check-Update (Device Secret Auth)
# =============================================================================

@app.post("/check-update")
def check_update(
    x_device_mac:       Optional[str] = Header(default=None),
    x_device_secret:    Optional[str] = Header(default=None),
    x_firmware_version: Optional[str] = Header(default=None),
    x_device_battery:   Optional[str] = Header(default=None),
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
    if x_device_battery is not None:
        try:
            device.battery = int(x_device_battery)
        except ValueError:
            pass
    db.commit()

    # ── Step 4: Cascading Resolution ──────────────────────────────────────
    # Priority 1: per-device developer override pin.
    resolved_release: Optional[FirmwareRelease] = None
    if device.firmware_override_id:
        resolved_release = db.query(FirmwareRelease).filter(
            FirmwareRelease.id == device.firmware_override_id
        ).first()

    # Priority 2: application group fleet target.
    if resolved_release is None and device.application_group_id:
        group = db.query(ApplicationGroup).filter(
            ApplicationGroup.id == device.application_group_id
        ).first()
        if group and group.target_release_id:
            resolved_release = db.query(FirmwareRelease).filter(
                FirmwareRelease.id == group.target_release_id
            ).first()

    # ── Step 5: Deployment decision ───────────────────────────────────────
    if resolved_release is None:
        return Response(status_code=204)

    # CRITICAL: Prevent Cross-Profile Bricking
    if device.device_profile_id and resolved_release.device_profile_id != device.device_profile_id:
        print(f"WARNING: Profile mismatch! Device {device.mac_address} blocked from bad OTA.")
        return Response(status_code=204)

    if not is_newer_version(resolved_release.version, x_firmware_version):
        return Response(status_code=204)

    if not os.path.exists(resolved_release.file_path):
        print(f"WARNING: FirmwareRelease id={resolved_release.id} file missing: {resolved_release.file_path}")
        return Response(status_code=204)

    device.last_ota_status = f"update_dispatched:{resolved_release.version}"
    db.commit()

    return FileResponse(
        resolved_release.file_path,
        media_type="application/octet-stream",
        filename=os.path.basename(resolved_release.file_path),
        headers={"X-Firmware-Version": resolved_release.version},
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
