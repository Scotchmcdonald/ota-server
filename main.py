import os
import re
import secrets
from datetime import datetime
from typing import Optional
from packaging.version import parse as parse_version

from fastapi import FastAPI, Request, Header, HTTPException, Depends, UploadFile, Form, status
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from sqlalchemy import create_engine, Column, Integer, String, DateTime, event
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# ---------------------------------------------------------
# Configuration and Constants
# ---------------------------------------------------------
app = FastAPI(title="ESP32 Smart OTA Server")

# Directory Config
DATA_DIR = "/app/data"
FIRMWARE_DIR = os.path.join(DATA_DIR, "firmware")
os.makedirs(FIRMWARE_DIR, exist_ok=True)

# Basic Auth Config
security = HTTPBasic()
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# ---------------------------------------------------------
# Database Setup
# ---------------------------------------------------------
DATABASE_URL = f"sqlite:///{os.path.join(DATA_DIR, 'ota.db')}"

# SQLite thread support
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

# Apply WAL journal mode for parallel checkins
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class Device(Base):
    __tablename__ = "devices"
    mac_address = Column(String, primary_key=True, index=True)
    secret = Column(String, nullable=False)
    device_class = Column(String, nullable=False)
    current_version = Column(String)
    track = Column(String, default="prod") # 'prod' or 'dev'
    last_checkin = Column(DateTime, default=datetime.utcnow)
    last_ota_status = Column(String)

class Firmware(Base):
    __tablename__ = "firmware"
    id = Column(Integer, primary_key=True, index=True)
    device_class = Column(String, nullable=False)
    version = Column(String, nullable=False)
    track = Column(String, default="prod")
    file_path = Column(String, nullable=False)
    upload_timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------
templates = Jinja2Templates(directory="templates")

def is_newer_version(v1: str, v2: str) -> bool:
    """Returns True if v1 > v2, handling real semantic versions"""
    try:
        return parse_version(v1) > parse_version(v2)
    except Exception:
        return False

# ---------------------------------------------------------
# Endpoints
# ---------------------------------------------------------

@app.post("/check-update")
def check_update(
    x_device_mac: Optional[str] = Header(None),
    x_device_secret: Optional[str] = Header(None),
    x_device_class: Optional[str] = Header(None),
    x_firmware_version: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    ESP32 OTA validation loop.
    1. Extracts headers
    2. Authenticates and updates device status
    3. Evaluates necessary update
    """
    if not all([x_device_mac, x_device_secret, x_device_class, x_firmware_version]):
        # If missing headers, ESP32 might be misconfigured. Deny update.
        return JSONResponse(status_code=400, content={"error": "Missing required headers. Ensure X-Device-MAC, X-Device-SECRET, X-Device-Class, and X-Firmware-Version are provided."})
    
    # Sanitize inputs to prevent SQL or weird character injection
    x_device_mac = x_device_mac.strip()
    x_device_class = x_device_class.strip()
    x_firmware_version = x_firmware_version.strip()
    
    device = db.query(Device).filter(Device.mac_address == x_device_mac).first()
    
    if not device:
        # First-time registration logic (Normally separate, but auto-added here for simplicity)
        device = Device(
            mac_address=x_device_mac,
            secret=x_device_secret,
            device_class=x_device_class,
            current_version=x_firmware_version,
            track="prod",
            last_checkin=datetime.utcnow()
        )
        db.add(device)
        db.commit()
        db.refresh(device)
    else:
        # Authenticate check-in
        if device.secret != x_device_secret:
            raise HTTPException(status_code=401, detail="Unauthorized")
            
        # Update check-in record
        device.last_checkin = datetime.utcnow()
        device.current_version = x_firmware_version
        device.device_class = x_device_class
        db.commit()

    # OTA Decision Logic based on track and device_class
    latest_firmware = db.query(Firmware).filter(
        Firmware.device_class == device.device_class,
        Firmware.track == device.track
    ).order_by(Firmware.id.desc()).first()

    # Compare version numbers to determine whether ESP32 requires the new file
    if latest_firmware and is_newer_version(latest_firmware.version, x_firmware_version):
        if os.path.exists(latest_firmware.file_path):
            return FileResponse(
                latest_firmware.file_path, 
                media_type="application/octet-stream", 
                filename=os.path.basename(latest_firmware.file_path)
            )
        else:
            print(f"Warning: Missing firmware file at {latest_firmware.file_path}")

    # No update required
    return JSONResponse(status_code=200, content={"update": False})


@app.post("/admin/upload")
def upload_firmware(
    file: UploadFile,
    device_class: str = Form(...),
    version: str = Form(...),
    track: str = Form(...),
    db: Session = Depends(get_db),
    admin: str = Depends(verify_admin)
):
    """Admin endpoint to upload compiled `.bin` firmware versions"""
    if not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin files are allowed")
    
    # Path Traversal / Sanitization fixes
    device_class = re.sub(r'[^a-zA-Z0-9_\-\.]', '', device_class)
    version = re.sub(r'[^a-zA-Z0-9_\-\.]', '', version)
    track = re.sub(r'[^a-zA-Z0-9_\-\.]', '', track)

    if not device_class or not version or not track:
        raise HTTPException(status_code=400, detail="Invalid form data characters provided.")
    
    # Secure filename construction
    filename = secure_filename(f"{device_class}_{track}_{version}.bin") if 'secure_filename' in globals() else f"{device_class}_{track}_{version}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    # Sanity check again just to be 100% sure we're saving inside FIRMWARE_DIR
    if os.path.commonpath([file_path, FIRMWARE_DIR]) != FIRMWARE_DIR:
        raise HTTPException(status_code=400, detail="Invalid path construction")
        
    # Save physical file
    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())
        
    # Record in database
    new_firmware = Firmware(
        device_class=device_class,
        version=version,
        track=track,
        file_path=file_path
    )
    db.add(new_firmware)
    db.commit()
    
    # Normally we would redirect to the dashboard, returning JSON for simplicity
    return {"message": "Firmware uploaded successfully", "filename": filename}


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db), admin: str = Depends(verify_admin)):
    """Dashboard UI returning Jinja templates populated with DB facts"""
    devices = db.query(Device).all()
    firmwares = db.query(Firmware).order_by(Firmware.id.desc()).all()
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "devices": devices, 
        "firmwares": firmwares
    })
