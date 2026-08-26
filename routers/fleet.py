import json
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from database import get_db
from deps import require_admin, _scope_slug, _resolve_scope_selection
from utils import _tag_gap, _effective_device_tags
from schemas import DeployPreviewRequest
from models import Fleet, Device, VersionedRelease, Tag, ReleaseStatus, UpdateMode, ScopeType, User

router = APIRouter()


# =============================================================================
# Fleet CRUD
# =============================================================================

@router.post("/admin/fleets/add")
def admin_add_fleet(
    name: str = Form(...),
    description: str = Form(""),
    scope: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    name_clean = name.strip()
    if not name_clean:
        raise HTTPException(status_code=400, detail="Fleet name is required.")
    if db.query(Fleet).filter(Fleet.name == name_clean).first():
        raise HTTPException(status_code=409, detail="Fleet already exists.")
    scope_type, scope_id, scope_name = _resolve_scope_selection(scope, current_user, db)
    fleet = Fleet(
        name=name_clean,
        description=(description or "").strip() or None,
        scope_type=scope_type,
        scope_id=scope_id,
    )
    db.add(fleet)
    db.commit()
    return RedirectResponse(url="/dashboard?top=settings&sub=fleets", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/fleets/delete/{fleet_id}")
def admin_delete_fleet(
    fleet_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    fleet = db.query(Fleet).filter(Fleet.id == fleet_id).first()
    if not fleet:
        raise HTTPException(status_code=404, detail="Fleet not found.")
    db.query(Device).filter(Device.fleet_id == fleet_id).update({"fleet_id": None}, synchronize_session=False)
    db.delete(fleet)
    db.commit()
    return RedirectResponse(url="/dashboard?top=settings&sub=fleets", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/fleets/{fleet_id}/edit")
def admin_edit_fleet(
    fleet_id: int,
    name: str = Form(...),
    description: str = Form(""),
    tags_json: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    fleet = db.query(Fleet).filter(Fleet.id == fleet_id).first()
    if not fleet:
        raise HTTPException(status_code=404, detail="Fleet not found.")
    fleet.name = name.strip()
    fleet.description = (description or "").strip() or None
    if tags_json:
        try:
            tags_by_cat = json.loads(tags_json)
        except (ValueError, TypeError):
            tags_by_cat = {}
        if isinstance(tags_by_cat, dict):
            _attach_tags_to_release(fleet, tags_by_cat, db)
    db.commit()
    return RedirectResponse(url="/dashboard?top=settings&sub=fleets", status_code=status.HTTP_303_SEE_OTHER)


def _attach_tags_to_release(release, tags_by_cat: dict, db: Session) -> None:
    """
    Attach (additive, not replacing) tags to a freshly-created release.
    Auto-creates any tag name not already present in that category.
    Unknown categories fall back to 'custom'.
    """
    from utils import TAG_CATEGORIES
    from models import Tag
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


# =============================================================================
# Fleet Deploy - shared gap analysis
# =============================================================================

def _resolve_target_releases(fleet_id: int, firmware_name: str, firmware_version: Optional[str], um: UpdateMode, db: Session):
    """
    Find every Approved VersionedRelease matching firmware_name (and version,
    if FIXED) across whichever compute_modules this fleet's devices actually
    use. A fleet can span multiple hardware types, so this is normally more
    than one release - one per compute_module variant.

    Returns (target_compute_modules, releases). target_compute_modules is
    empty when the fleet has no devices with a known compute_module yet -
    callers should treat that as "nothing to target" rather than querying
    further, since an empty compute_module list would otherwise reach
    or_() with zero arguments.
    """
    target_compute_modules = [
        d.compute_module for d in db.query(Device.compute_module).filter(Device.fleet_id == fleet_id).distinct().all()
        if d.compute_module
    ]
    if not target_compute_modules:
        return target_compute_modules, []

    release_query = db.query(VersionedRelease).filter(
        VersionedRelease.firmware_name == firmware_name,
        VersionedRelease.compute_module == or_(*target_compute_modules),
        VersionedRelease.status == ReleaseStatus.Approved,
    )
    if um == UpdateMode.FIXED and firmware_version:
        release_query = release_query.filter(VersionedRelease.firmware_version == firmware_version)

    return target_compute_modules, release_query.all()


def _compute_gap_summary(devices, releases):
    """
    Per-device tag-subset-match against whichever release shares that
    device's compute_module. Returns (device_info_list, exact_count,
    drift_count, blocked_count) - device_info_list is only used by the
    preview endpoint, the commit endpoint just needs the counts.
    """
    device_info_list = []
    exact_count = drift_count = blocked_count = 0

    for dev in devices:
        dev_tag_names = _effective_device_tags(dev)
        matching_release = next((r for r in releases if r.compute_module == dev.compute_module), None)
        if matching_release is None:
            gap = {"subset_match": False, "exact_match": False, "missing_tags": [], "extra_tags": sorted(dev_tag_names)}
        else:
            release_tags = {t.name for t in (matching_release.tags or [])}
            gap = _tag_gap(release_tags, dev_tag_names)

        device_info_list.append({
            "mac_address": dev.mac_address,
            "nickname": dev.nickname,
            "compute_module": dev.compute_module,
            "tag_names": list(dev_tag_names),
            "gap": gap,
            "hardware_match": matching_release is not None,
        })

        if gap["subset_match"]:
            if gap["exact_match"]:
                exact_count += 1
            else:
                drift_count += 1
        else:
            blocked_count += 1

    return device_info_list, exact_count, drift_count, blocked_count


# =============================================================================
# Fleet Deploy Preview
# =============================================================================

@router.post("/api/deploy/preview")
def deploy_preview(
    body: DeployPreviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Preview gap analysis for a fleet deploy - read-only, commits nothing."""
    _ = current_user
    fleet = db.query(Fleet).filter(Fleet.id == body.fleet_id).first()
    if not fleet:
        raise HTTPException(status_code=404, detail="Fleet not found.")

    try:
        um = UpdateMode(body.update_mode)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid update_mode: {body.update_mode}. Must be LATEST or FIXED.")

    if um == UpdateMode.FIXED and not body.firmware_version:
        raise HTTPException(status_code=400, detail="firmware_version is required when update_mode is FIXED.")

    target_compute_modules, releases = _resolve_target_releases(fleet.id, body.firmware_name, body.firmware_version, um, db)
    devices = db.query(Device).filter(Device.fleet_id == fleet.id).all()

    if not target_compute_modules:
        return JSONResponse(status_code=200, content={
            "fleet_id": fleet.id,
            "firmware_name": body.firmware_name,
            "firmware_version": body.firmware_version,
            "devices": [],
            "missing_hardware": [],
            "summary": {"total_devices": 0, "exact_match_count": 0, "drift_count": 0, "blocked_count": 0},
            "requires_acknowledgment": False,
        })

    device_info_list, exact_count, drift_count, blocked_count = _compute_gap_summary(devices, releases)

    # Missing hardware - compute modules this fleet actually uses with no
    # approved release at all for this firmware_name/version.
    covered_computes = {r.compute_module for r in releases}
    missing_hardware = sorted(set(target_compute_modules) - covered_computes)

    requires_ack = drift_count > 0 or blocked_count > 0 or len(missing_hardware) > 0

    return JSONResponse(status_code=200, content={
        "fleet_id": fleet.id,
        "firmware_name": body.firmware_name,
        "firmware_version": body.firmware_version,
        "devices": device_info_list,
        "missing_hardware": missing_hardware,
        "summary": {
            "total_devices": len(devices),
            "exact_match_count": exact_count,
            "drift_count": drift_count,
            "blocked_count": blocked_count,
        },
        "requires_acknowledgment": requires_ack,
    })


# =============================================================================
# Fleet Deploy Commit
# =============================================================================

@router.post("/api/fleet/{fleet_id}/deploy")
def deploy_to_fleet(
    fleet_id: int,
    request: Request,
    update_mode: str = Form(...),
    firmware_name: str = Form(...),
    firmware_version: Optional[str] = Form(None),
    acknowledge_gaps: bool = Form(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Commit a firmware deployment to a fleet."""
    _ = current_user
    fleet = db.query(Fleet).filter(Fleet.id == fleet_id).first()
    if not fleet:
        raise HTTPException(status_code=404, detail="Fleet not found.")

    try:
        um = UpdateMode(update_mode)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid update_mode: {update_mode}. Must be LATEST or FIXED.")

    if um == UpdateMode.FIXED and not firmware_version:
        raise HTTPException(status_code=400, detail="firmware_version is required when update_mode is FIXED.")

    target_compute_modules, releases = _resolve_target_releases(fleet_id, firmware_name, firmware_version, um, db)
    if not target_compute_modules:
        return {"status": "skipped", "message": "No valid devices in this fleet to target."}

    devices = db.query(Device).filter(Device.fleet_id == fleet.id).all()
    _, exact_count, drift_count, blocked_count = _compute_gap_summary(devices, releases)

    requires_ack = drift_count > 0 or blocked_count > 0

    if requires_ack and not acknowledge_gaps:
        return JSONResponse(
            status_code=400,
            content={
                "detail": "Gaps detected. Acknowledge to proceed.",
                "gap_analysis": {
                    "total_devices": len(devices),
                    "exact_match_count": exact_count,
                    "drift_count": drift_count,
                    "blocked_count": blocked_count,
                },
            },
        )

    version_clean = firmware_version if um == UpdateMode.FIXED else None
    fleet.update_mode = um
    fleet.target_firmware_name = firmware_name.strip()
    fleet.target_firmware_version = version_clean.strip() if version_clean else None
    fleet.target_oneshot_release_id = None
    db.commit()

    return JSONResponse(status_code=200, content={
        "message": "Fleet deployment committed.",
        "fleet_id": fleet.id,
        "update_mode": fleet.update_mode.value,
        "firmware_name": fleet.target_firmware_name,
        "firmware_version": fleet.target_firmware_version,
    })
