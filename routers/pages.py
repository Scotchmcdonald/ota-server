from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from packaging.version import parse as parse_version
from sqlalchemy import or_, and_, false
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user, _scope_slug
from utils import _normalize_firmware_name, _normalize_firmware_version, TAG_CATEGORIES
from models import User, Team, Device, Fleet, Tag, VersionedRelease, OneShotRelease, AllowedEmail, AllowedDomain, APIKey, ScopeType, UserRole, ReleaseStatus, ComputeModule

templates = Jinja2Templates(directory="templates")

router = APIRouter()


@router.get("/dashboard", response_class=HTMLResponse)
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

    versioned_releases = db.query(VersionedRelease).filter(
        VersionedRelease.status == ReleaseStatus.Approved
    ).order_by(VersionedRelease.id.desc()).all()
    staging_versioned_release_rows = db.query(VersionedRelease).filter(
        VersionedRelease.status == ReleaseStatus.Staging
    ).order_by(VersionedRelease.id.desc()).all()

    staging_release_rows = [
        {
            "id": release.id,
            "firmware_name": release.firmware_name,
            "compute_module": release.compute_module,
            "tags": [{"name": t.name, "category": t.category, "color": t.color} for t in (release.tags or [])],
            "upload_timestamp": release.upload_timestamp,
        }
        for release in staging_versioned_release_rows
    ]

    teams = db.query(Team).all()
    team_name_by_id = {team.id: team.name for team in teams}

    fleet_nodes = []
    for device in visible_claimed_devices:
        all_tags = device.tags or []
        tag_names = [t.name for t in all_tags]
        tags_by_category = {}
        for t in all_tags:
            cat = t.category or "custom"
            tags_by_category.setdefault(cat, []).append({"name": t.name, "color": t.color})
        last_checkin = device.last_checkin
        is_online = bool(last_checkin and (datetime.utcnow() - last_checkin).total_seconds() <= 900)
        if device.scope_type == ScopeType.Personal or (device.scope_type is None and device.scope_id == user_info.id):
            device_scope_label = "Personal"
            device_scope_slug = "personal"
        elif device.scope_type == ScopeType.Team and device.scope_id:
            device_scope_label = team_name_by_id.get(device.scope_id, "Unknown Team")
            device_scope_slug = _scope_slug(device_scope_label)
        else:
            device_scope_label = "Unknown"
            device_scope_slug = "unknown"
        fleet_nodes.append({
            "mac": device.mac_address,
            "scope": device_scope_label,
            "scope_slug": device_scope_slug,
            "tags": tag_names,
            "tags_csv": ", ".join(tag_names),
            "tags_by_category": tags_by_category,
            "fw": device.current_firmware_version or "unknown",
            "batt": int(device.battery) if device.battery is not None else 0,
            "status": "online" if is_online else "offline",
            "fleet_id": device.fleet_id,
            "fleet_name": device.fleet.name if device.fleet else None,
            "target_oneshot_release_id": device.target_oneshot_release_id,
            "update_mode": device.update_mode.value,
            "target_firmware_name": device.target_firmware_name,
            "target_firmware_version": device.target_firmware_version,
            "heartbeat_interval": device.heartbeat_interval,
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
    new_key_token_id = request.session.pop("new_key_token_id_flash", None)
    fleets = db.query(Fleet).order_by(Fleet.name.asc()).all()
    compute_modules = db.query(ComputeModule).order_by(ComputeModule.name.asc()).all()
    all_tags = db.query(Tag).order_by(Tag.category.asc(), Tag.name.asc()).all()
    one_shot_releases = db.query(OneShotRelease).order_by(OneShotRelease.id.desc()).all()

    firmware_versions_by_name: dict[str, list[str]] = {}
    for release in versioned_releases:
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

    allowed_emails  = db.query(AllowedEmail).order_by(AllowedEmail.created_at).all()  if user_info.role == UserRole.Admin else []
    allowed_domains = db.query(AllowedDomain).order_by(AllowedDomain.created_at).all() if user_info.role == UserRole.Admin else []
    admin_api_tokens = db.query(APIKey).join(User).order_by(APIKey.created_at.desc()).all() if user_info.role == UserRole.Admin else []
    admin_teams = db.query(Team).order_by(Team.name.asc()).all() if user_info.role == UserRole.Admin else []
    admin_users = db.query(User).order_by(User.email.asc()).all() if user_info.role == UserRole.Admin else []

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user":                 session_user,
            "db_user":              user_info,
            "devices":              visible_claimed_devices,
            "versioned_releases":   versioned_releases,
            "staging_versioned_release_rows": staging_release_rows,
            "api_tokens":           api_tokens,
            "new_key":              new_key,
            "new_key_token_id":     new_key_token_id,
            "fleets":               fleets,
            "compute_modules":      compute_modules,
            "all_tags":             all_tags,
            "one_shot_releases":    one_shot_releases,
            "firmware_names":       firmware_names,
            "firmware_versions_by_name": firmware_versions_by_name,
            "scope_options":        scope_options,
            "fleet_nodes":          fleet_nodes,
            "unclaimed_devices":    unclaimed_rows,
            "allowed_emails":       allowed_emails,
            "allowed_domains":      allowed_domains,
            "admin_api_tokens":     admin_api_tokens,
            "admin_teams":          admin_teams,
            "admin_users":          admin_users,
            "tag_categories":       TAG_CATEGORIES,
        },
    )
