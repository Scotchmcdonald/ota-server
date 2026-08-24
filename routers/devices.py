import json
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user, require_admin, has_scope_permission, _resolve_scope_selection, _scope_slug
from utils import _parse_optional_int, _upsert_tags_for_device, TAG_CATEGORIES
from schemas import ClaimDevicePayload
from models import Device, Fleet, Tag, UpdateMode, ScopeType, User, UserRole, OneShotRelease
from auth import get_current_user_from_db, get_current_user_scopes

router = APIRouter()


@router.post("/devices/{mac_address}/claim")
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


@router.post("/api/claim")
def claim_device_from_form(
    request: Request,
    mac: str = Form(...),
    scope: str = Form(...),
    hardware_type: str = Form(...),
    fleet_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ = request

    hardware_type = hardware_type.strip()
    if not hardware_type:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ESP hardware type is required to claim a device.")

    device = db.query(Device).filter(Device.mac_address == mac).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")
    if device.claimed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device is already claimed.")

    target_scope_type, target_scope_id, _ = _resolve_scope_selection(scope, current_user, db)
    if not has_scope_permission(current_user, target_scope_type, target_scope_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to claim hardware into this scope.",
        )

    parsed_fleet_id = _parse_optional_int(fleet_id, "fleet_id")
    if parsed_fleet_id is not None:
        if not db.query(Fleet).filter(Fleet.id == parsed_fleet_id).first():
            raise HTTPException(status_code=404, detail="Fleet not found.")

    device.claimed = True
    device.scope_type = target_scope_type
    device.scope_id = target_scope_id
    device.fleet_id = parsed_fleet_id
    device.secret = secrets.token_urlsafe(32)

    # Claim only sets the device's immutable hardware type. Every other tag
    # is assigned later via Manage Device / Fleet tooling, not at enrollment.
    _upsert_tags_for_device(device, [hardware_type], db, actor_is_admin=current_user.role == UserRole.Admin)
    for t in device.tags or []:
        if t.name == hardware_type:
            t.category = "hardware"

    db.commit()
    return RedirectResponse(url="/dashboard?top=devices&sub=onboard", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/api/fleet/devices/{mac}/update")
def update_fleet_device(
    mac: str,
    request: Request,
    scope: str = Form(...),
    tags: str = Form(""),
    tags_json: str = Form(""),
    fleet_id: Optional[str] = Form(None),
    update_mode: Optional[str] = Form(None),
    target_firmware_name: Optional[str] = Form(None),
    target_firmware_version: Optional[str] = Form(None),
    target_oneshot_release_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ = request

    if tags_json:
        try:
            tags_by_cat = json.loads(tags_json)
        except (ValueError, TypeError):
            tags_by_cat = {}
    else:
        tags_by_cat = {"custom": [t.strip() for t in tags.split(",") if t.strip()]}

    device = db.query(Device).filter(Device.mac_address == mac).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
    if not device.claimed:
        raise HTTPException(status_code=400, detail="Cannot manage an unclaimed device.")

    if not has_scope_permission(current_user, device.scope_type or ScopeType.Personal, device.scope_id or current_user.id):
        raise HTTPException(status_code=403, detail="You do not have permission to manage this device.")

    target_scope_type, target_scope_id, _ = _resolve_scope_selection(scope, current_user, db)
    if not has_scope_permission(current_user, target_scope_type, target_scope_id):
        raise HTTPException(status_code=403, detail="You do not have permission to assign this scope.")

    parsed_fleet_id = _parse_optional_int(fleet_id, "fleet_id")
    if parsed_fleet_id is not None:
        if not db.query(Fleet).filter(Fleet.id == parsed_fleet_id).first():
            raise HTTPException(status_code=404, detail="Fleet not found.")

    if parsed_fleet_id is not None:
        device.fleet_id = parsed_fleet_id
    if update_mode is not None and update_mode.strip():
        device.update_mode = UpdateMode(update_mode.strip())
    if target_firmware_name is not None:
        device.target_firmware_name = target_firmware_name.strip() or None
    if target_firmware_version is not None:
        device.target_firmware_version = target_firmware_version.strip() or None
    if target_oneshot_release_id is not None and target_oneshot_release_id.strip():
        ones_id = _parse_optional_int(target_oneshot_release_id, "target_oneshot_release_id")
        if ones_id:
            if not db.query(OneShotRelease).filter(OneShotRelease.id == ones_id).first():
                raise HTTPException(status_code=404, detail="OneShot release not found.")
            device.target_oneshot_release_id = ones_id
    flat_tags = [name for names in tags_by_cat.values() for name in names]
    _upsert_tags_for_device(device, flat_tags, db, actor_is_admin=current_user.role == UserRole.Admin)

    for cat, tag_names in tags_by_cat.items():
        for t in device.tags or []:
            if t.name in tag_names:
                t.category = cat

    db.commit()
    return RedirectResponse(url="/dashboard?top=devices&sub=fleet", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/api/tags/manager")
def get_tags_manager_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user

    all_tags = db.query(Tag).order_by(Tag.category.asc(), Tag.name.asc()).all()

    tags_data = []
    for tag in all_tags:
        device_count = len(tag.devices) if tag.devices else 0
        release_count = len(tag.versioned_releases) if tag.versioned_releases else 0
        tags_data.append({
            "id": tag.id,
            "name": tag.name,
            "category": tag.category,
            "color": tag.color or "#3b82f6",
            "device_count": device_count,
            "release_count": release_count,
        })

    return JSONResponse(status_code=200, content={
        "tags": tags_data,
        "categories": TAG_CATEGORIES,
    })


@router.post("/api/tags")
def create_tag(
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = request
    _ = current_user

    name = body.get("name", "").strip()
    category = body.get("category", "") or "custom"
    color = body.get("color", "") or "#3b82f6"

    if not name:
        return JSONResponse(status_code=400, content={"error": "Tag name is required."})

    existing = db.query(Tag).filter(Tag.name == name, Tag.category == category).first()
    if existing:
        return JSONResponse(status_code=200, content={"id": existing.id, "name": existing.name, "category": existing.category, "color": existing.color or "#3b82f6"})

    new_tag = Tag(
        name=name,
        category=category,
        color=color or "#3b82f6",
    )
    db.add(new_tag)
    db.commit()
    db.refresh(new_tag)

    return JSONResponse(status_code=201, content={
        "id": new_tag.id,
        "name": new_tag.name,
        "category": new_tag.category,
        "color": new_tag.color or "#3b82f6",
    })


@router.post("/api/tags/{tag_id}")
async def delete_tag(
    tag_id: int,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = request
    _ = current_user

    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        return JSONResponse(status_code=404, content={"error": "Tag not found."})

    # Remove tag from all devices and releases
    for device in tag.devices:
        if tag in device.tags:
            device.tags.remove(tag)
    for release in tag.versioned_releases:
        if tag in release.tags:
            release.tags.remove(tag)

    db.delete(tag)
    db.commit()
    return JSONResponse(status_code=200, content={"success": True})


@router.post("/api/firmware/releases/{release_id}/tags")
async def update_firmware_release_tags(
    release_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = request
    _ = current_user

    release = db.query(VersionedRelease).filter(VersionedRelease.id == release_id).first()
    if not release:
        return JSONResponse(status_code=404, content={"error": "Versioned release not found."})

    form_data = await request.Form()
    tags_json = form_data.get("tags_json", "")

    if tags_json:
        try:
            tags_by_cat = json.loads(tags_json)
        except (ValueError, TypeError):
            tags_by_cat = {}
    else:
        tags_by_cat = {}

    release.tags = []

    for cat, tag_names in tags_by_cat.items():
        for tag_name in tag_names:
            tag = db.query(Tag).filter(Tag.name == tag_name, Tag.category == cat).first()
            if not tag:
                tag = Tag(name=tag_name, category=cat or "custom", color="#3b82f6")
                db.add(tag)
                db.flush()
            release.tags.append(tag)

    db.commit()

    return JSONResponse(status_code=200, content={"status": "ok"})


@router.post("/api/fleet/unclaim/{mac}")
def unclaim_device(
    mac: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    device = db.query(Device).filter(Device.mac_address == mac).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    device.claimed = False
    device.scope_type = None
    device.scope_id = None
    device.fleet_id = None
    device.target_oneshot_release_id = None
    device.target_firmware_name = None
    device.target_firmware_version = None
    device.update_mode = UpdateMode.LATEST
    device.secret = "pending_claim"
    db.commit()
    return RedirectResponse(url="/dashboard?top=devices&sub=fleet", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/api/fleet/unclaimed/purge")
def purge_unclaimed_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete every auto-registered device that has never been claimed."""
    _ = current_user
    deleted = db.query(Device).filter(Device.claimed == False).delete(synchronize_session=False)
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Unclaimed devices purged.", "deleted": deleted})


# =============================================================================
# Bulk Device Tag Editing
# =============================================================================

@router.post("/api/fleet/bulk-tags")
async def bulk_device_tags(
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user

    macs = body.get("device_macs", [])
    tag_id = body.get("tag_id")
    action = body.get("action", "add")

    if not macs or not tag_id:
        return JSONResponse(status_code=400, content={"error": "MACs and tag_id required."})

    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        return JSONResponse(status_code=404, content={"error": "Tag not found."})

    added = 0
    removed = 0

    for mac in macs:
        device = db.query(Device).filter(Device.mac_address == mac).first()
        if not device:
            continue

        if action == "add":
            if tag not in device.tags:
                device.tags.append(tag)
                added += 1
        elif action == "remove":
            if tag in device.tags:
                device.tags.remove(tag)
                removed += 1

    db.commit()
    return JSONResponse(status_code=200, content={"added": added, "removed": removed})
