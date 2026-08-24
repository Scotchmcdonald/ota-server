import os
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from packaging.version import parse as parse_version

from database import get_db, FIRMWARE_DIR
from deps import require_admin, get_current_user, _scope_slug
from utils import TAG_CATEGORIES, _sanitize_field, _resolve_compute_module_name
from models import VersionedRelease, OneShotRelease, ReleaseStatus, ComputeModule, Tag, User

router = APIRouter()


def _attach_tags_to_release(release, tags_by_cat: dict, db: Session) -> None:
    """
    Attach (additive, not replacing) tags to a freshly-created release.
    Auto-creates any tag name not already present in that category.
    Unknown categories fall back to 'custom'.
    """
    valid_categories = set(TAG_CATEGORIES.keys()) | {"custom"}
    for cat, tag_names in (tags_by_cat or {}).items():
        cat_clean = cat if cat in valid_categories else "custom"
        for tag_name in tag_names:
            tag_name = (tag_name or "").strip()
            if not tag_name:
                continue
            tag = db.query(Tag).filter(Tag.name == tag_name, Tag.category == cat_clean).first()
            if not tag:
                tag = Tag(name=tag_name, category=cat_clean, color="#3b82f6")
                db.add(tag)
                db.flush()
            if tag not in release.tags:
                release.tags.append(tag)
    db.commit()


def _process_versioned_upload(file, firmware_name, compute_module, db, actor_user, tags_json=None):
    """
    Shared versioned firmware upload for both web and M2M endpoints.
    Versioning is server-owned: every upload lands as status=Staging with no
    version assigned. An admin approves (assigns a version) or rejects it
    later via /api/releases/{id}/approve|reject.

    Returns:
        Tuple of (VersionedRelease, filename)
    """
    _ = actor_user
    if not file.filename or not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin firmware files are accepted.")

    firmware_name_clean = _sanitize_field(firmware_name)
    if not firmware_name_clean:
        raise HTTPException(status_code=400, detail="Invalid firmware name.")

    compute_module_clean = _resolve_compute_module_name(compute_module, db)
    compute_module_slug = _sanitize_field(compute_module_clean)
    if not compute_module_slug:
        raise HTTPException(status_code=400, detail="Invalid compute_module.")

    content = file.file.read()

    release = VersionedRelease(
        firmware_name=firmware_name_clean,
        firmware_version=None,
        status=ReleaseStatus.Staging,
        file_path="",
        compute_module=compute_module_clean,
    )
    db.add(release)
    db.flush()

    firmware_name_slug = _sanitize_field(firmware_name_clean)
    filename = f"{compute_module_slug}_{firmware_name_slug}_staging{release.id}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    if not os.path.realpath(file_path).startswith(os.path.realpath(FIRMWARE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid path construction.")

    with open(file_path, "wb") as buf:
        buf.write(content)
    release.file_path = file_path

    db.commit()
    db.refresh(release)

    if not db.query(ComputeModule).filter(ComputeModule.name == compute_module_clean).first():
        db.add(ComputeModule(name=compute_module_clean))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()

    if tags_json:
        try:
            tags_by_cat = json.loads(tags_json)
        except (ValueError, TypeError):
            tags_by_cat = {}
        if isinstance(tags_by_cat, dict):
            _attach_tags_to_release(release, tags_by_cat, db)

    return release, filename


def _process_oneshot_upload(file, compute_module, notes, db, actor_user):
    """
    Upload a one-shot firmware binary. No SemVer, no approval lifecycle.
    Returns (OneShotRelease, filename).
    """
    _ = actor_user
    if not file.filename or not file.filename.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin firmware files are accepted.")

    compute_module_clean = _resolve_compute_module_name(compute_module, db)
    compute_module_slug = _sanitize_field(compute_module_clean)
    if not compute_module_slug:
        raise HTTPException(status_code=400, detail="Invalid compute_module.")

    content = file.file.read()

    release = OneShotRelease(
        filename="",
        upload_date=datetime.utcnow(),
        compute_module=compute_module_clean,
        notes=notes or None,
    )
    db.add(release)
    db.flush()

    filename = f"{compute_module_slug}_oneshot{release.id}.bin"
    file_path = os.path.join(FIRMWARE_DIR, filename)

    if not os.path.realpath(file_path).startswith(os.path.realpath(FIRMWARE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid path construction.")

    with open(file_path, "wb") as buf:
        buf.write(content)
    release.filename = filename
    release.file_path = file_path if hasattr(release, 'file_path') else file_path

    db.commit()
    db.refresh(release)

    if not db.query(ComputeModule).filter(ComputeModule.name == compute_module_clean).first():
        db.add(ComputeModule(name=compute_module_clean))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()

    return release, filename


@router.post("/admin/upload-firmware", status_code=201)
@router.post("/api/upload-firmware", status_code=201)
def upload_firmware_m2m(
    request:           Request,
    file:              UploadFile,
    firmware_name:     str = Form(...),
    compute_module:    str = Form(...),
    tags_json:         Optional[str] = Form(None),
    db:                Session = Depends(get_db),
    admin_actor:       User = Depends(require_admin),
):
    """
    Firmware upload endpoint supporting:
    - M2M CI/CD uploads via X-Admin-Key header
    - Web dashboard uploads via authenticated session

    Versioning is server-owned — every upload lands as an unversioned Staging
    release. See /api/releases/{id}/approve to assign a version.
    """
    _ = request

    release, filename = _process_versioned_upload(
        file=file,
        firmware_name=firmware_name,
        compute_module=compute_module,
        db=db,
        actor_user=admin_actor,
        tags_json=tags_json,
    )

    return JSONResponse(status_code=201, content={
        "message":         f"Uploaded as Staging Build #{release.id}, awaiting approval.",
        "firmware_release_id": release.id,
        "firmware_name":   release.firmware_name,
        "status":          release.status.value,
        "filename":        filename,
        "uploaded_by":     admin_actor.email,
    })


# =============================================================================
# Web Portal: Firmware Upload (OAuth-protected)
# =============================================================================

@router.post("/admin/upload", status_code=201)
def upload_firmware_web(
    request:           Request,
    file:              UploadFile,
    firmware_name:     str = Form(...),
    compute_module:    str = Form(...),
    tags_json:         Optional[str] = Form(None),
    db:                Session = Depends(get_db),
):
    """
    Upload a firmware binary. Lands as an unversioned Staging release
    awaiting admin approval.
    """
    session_user = request.session.get("user")
    if not session_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    release, _ = _process_versioned_upload(
        file=file,
        firmware_name=firmware_name,
        compute_module=compute_module,
        db=db,
        actor_user=get_current_user(request, db, request.headers.get("Authorization")),
        tags_json=tags_json,
    )

    return JSONResponse(status_code=201, content={
        "message": f"Uploaded as Staging Build #{release.id}, awaiting approval.",
        "firmware_release_id": release.id,
    })


@router.post("/admin/upload-oneshot", status_code=201)
@router.post("/api/upload-oneshot", status_code=201)
def upload_oneshot(
    request:        Request,
    file:           UploadFile,
    compute_module: str = Form(...),
    notes:          str = Form(""),
    scope:          str = Form(""),
    db:             Session = Depends(get_db),
    admin_actor:    User = Depends(require_admin),
):
    """Upload a one-shot firmware binary (no SemVer, no approval)."""
    _ = request
    scope_slug = _scope_slug(scope)
    if not scope_slug:
        raise HTTPException(status_code=400, detail="Missing scope.")

    release, filename = _process_oneshot_upload(
        file=file,
        compute_module=compute_module,
        notes=notes,
        db=db,
        actor_user=admin_actor,
    )

    return JSONResponse(status_code=201, content={
        "message":           f"One-shot uploaded as #{release.id}.",
        "one_shot_release_id": release.id,
        "filename":          filename,
        "compute_module":    release.compute_module,
        "uploaded_by":       admin_actor.email,
    })


# =============================================================================
# Release Approval Workflow (Staging -> Approved / Rejected)
# =============================================================================

def _suggest_next_version(firmware_name: str, compute_module: str, db: Session) -> str:
    """
    Suggests the next patch-bump version for a (name, compute_module) target,
    based on the newest Approved release. Falls back to '1.0.0'.
    """
    candidates = db.query(VersionedRelease).filter(
        VersionedRelease.firmware_name == firmware_name,
        VersionedRelease.compute_module == compute_module,
        VersionedRelease.status == ReleaseStatus.Approved,
        VersionedRelease.firmware_version.isnot(None),
    ).all()
    if not candidates:
        return "1.0.0"

    best = max(candidates, key=lambda r: parse_version(r.firmware_version))
    parts = (list(parse_version(best.firmware_version).release) + [0, 0, 0])[:3]
    major, minor, micro = parts
    return f"{major}.{minor}.{micro + 1}"


@router.get("/api/releases/{release_id}/suggest-version")
def suggest_release_version(
    release_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    release = db.query(VersionedRelease).filter(VersionedRelease.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Versioned release not found.")
    suggested = _suggest_next_version(release.firmware_name, release.compute_module, db)
    return {"suggested_version": suggested}


@router.post("/api/releases/{release_id}/approve")
def approve_release(
    release_id: int,
    version: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Assigns a real version to a Staging release and promotes it to Approved."""
    _ = current_user
    release = db.query(VersionedRelease).filter(VersionedRelease.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Versioned release not found.")
    if release.status != ReleaseStatus.Staging:
        raise HTTPException(status_code=400, detail=f"Release is not in Staging (status={release.status.value}).")

    raw_version = (version or "").strip()
    version_clean = _sanitize_field(raw_version, allow_dots=True) if raw_version else ""
    if not version_clean:
        version_clean = _suggest_next_version(release.firmware_name, release.compute_module, db)

    existing = db.query(VersionedRelease.id).filter(
        VersionedRelease.firmware_name == release.firmware_name,
        VersionedRelease.firmware_version == version_clean,
        VersionedRelease.compute_module == release.compute_module,
        VersionedRelease.status == ReleaseStatus.Approved,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Version {version_clean} is already approved for this target.")

    release.firmware_version = version_clean
    release.status = ReleaseStatus.Approved

    db.commit()
    db.refresh(release)
    return {
        "message": "Release approved.",
        "firmware_release_id": release.id,
        "firmware_version": release.firmware_version,
        "status": release.status.value,
    }


@router.post("/api/releases/{release_id}/reject")
def reject_release(
    release_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Marks a Staging release Rejected. Kept on disk for history; never served."""
    _ = current_user
    release = db.query(VersionedRelease).filter(VersionedRelease.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Versioned release not found.")
    if release.status != ReleaseStatus.Staging:
        raise HTTPException(status_code=400, detail=f"Release is not in Staging (status={release.status.value}).")

    release.status = ReleaseStatus.Rejected
    db.commit()
    return {"message": "Release rejected.", "firmware_release_id": release.id, "status": release.status.value}
