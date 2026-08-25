from collections import defaultdict
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

    approved_release_rows = []
    for release in versioned_releases:
        is_stale = any(
            parse_version(other.firmware_version) > parse_version(release.firmware_version)
            for other in versioned_releases
            if other.id != release.id
            and other.firmware_name == release.firmware_name
            and other.compute_module == release.compute_module
        )
        approved_release_rows.append({
            "id": release.id,
            "firmware_name": release.firmware_name,
            "firmware_version": release.firmware_version,
            "compute_module": release.compute_module,
            "tags": [{"name": t.name, "category": t.category, "color": t.color} for t in (release.tags or [])],
            "upload_timestamp": release.upload_timestamp,
            "is_stale": is_stale,
        })

    # Warehouse tree: Name -> Tag combination -> Compute Module -> Versions
    # (newest first). Built from approved_release_rows so tags are already
    # plain dicts (name/category/color) and is_stale is already computed -
    # nothing here re-derives either.
    def _sort_versions_newest_first(rows):
        valid = []
        invalid = []
        for row in rows:
            try:
                valid.append((parse_version(row["firmware_version"]), row))
            except Exception:
                invalid.append(row)
        valid.sort(key=lambda pair: pair[0], reverse=True)
        return [row for _, row in valid] + sorted(invalid, key=lambda row: (row["firmware_version"] or ""))

    by_name: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for row in approved_release_rows:
        tag_key = tuple(sorted((t["category"], t["name"]) for t in row["tags"]))
        by_name[row["firmware_name"]][tag_key][row["compute_module"]].append(row)

    warehouse_tree = []
    for firmware_name in sorted(by_name.keys(), key=str.lower):
        tag_groups_dict = by_name[firmware_name]
        tag_groups = []
        name_count = 0
        for tag_key in sorted(tag_groups_dict.keys(), key=lambda k: ", ".join(n for _, n in k).lower()):
            compute_dict = tag_groups_dict[tag_key]
            tag_label = ", ".join(n for _, n in tag_key) if tag_key else "No Tags"
            computes = []
            group_count = 0
            group_tags = None
            for compute_module in sorted(compute_dict.keys(), key=str.lower):
                rows_sorted = _sort_versions_newest_first(compute_dict[compute_module])
                if group_tags is None and rows_sorted:
                    group_tags = rows_sorted[0]["tags"]
                for i, row in enumerate(rows_sorted):
                    row["is_latest"] = (i == 0)
                computes.append({
                    "compute_module": compute_module,
                    "versions": rows_sorted,
                    "count": len(rows_sorted),
                })
                group_count += len(rows_sorted)
            tag_groups.append({
                "label": tag_label,
                "tags": group_tags or [],
                "computes": computes,
                "count": group_count,
            })
            name_count += group_count
        warehouse_tree.append({
            "firmware_name": firmware_name,
            "tag_groups": tag_groups,
            "count": name_count,
        })

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

    # Tag suggestions for Manage Device: tags already used elsewhere in the
    # same fleet, so an admin can click instead of retyping. Derived from
    # fleet_nodes (already scoped to what this viewer can see) rather than a
    # fresh query. Hardware is excluded - it's immutable, assigned only at
    # claim, never editable here.
    fleet_tag_suggestions: dict = defaultdict(lambda: defaultdict(dict))
    for node in fleet_nodes:
        fid = node["fleet_id"]
        if not fid:
            continue
        for cat, cat_tags in node["tags_by_category"].items():
            if cat == "hardware":
                continue
            for t in cat_tags:
                fleet_tag_suggestions[fid][cat][t["name"]] = t["color"]

    fleet_tag_suggestions_output = {
        str(fid): {
            cat: [{"name": name, "color": color} for name, color in names.items()]
            for cat, names in cats.items()
        }
        for fid, cats in fleet_tag_suggestions.items()
    }

    # Fleet Audit: group claimed devices by (tag names, compute_module) per fleet
    fleet_audit: dict = {}
    for device in visible_claimed_devices:
        if not device.fleet_id:
            continue
        all_tags = device.tags or []
        tag_names = sorted([t.name for t in all_tags])
        key = (tuple(tag_names), device.compute_module or "")
        fid = device.fleet_id
        if fid not in fleet_audit:
            fleet_audit[fid] = {"fleet_name": (device.fleet.name if device.fleet else "Unknown"), "groups": {}}
        group = fleet_audit[fid]["groups"].setdefault(key, {
            "tag_names": tag_names,
            "compute_module": device.compute_module or "",
            "device_count": 0,
            "firmware_versions": set(),
            "sample_macs": [],
        })
        group["device_count"] += 1
        fw = device.current_firmware_version
        if fw:
            group["firmware_versions"].add(fw)
        else:
            group["firmware_versions"].add("unknown")
        group["sample_macs"].append(device.mac_address)

    fleet_audit_output: dict = {}
    for fid, data in fleet_audit.items():
        groups_list = []
        for key, grp in data["groups"].items():
            versions_list = sorted(grp["firmware_versions"])
            versions_display = ", ".join(versions_list)
            groups_list.append({
                "tag_names": grp["tag_names"],
                "compute_module": grp["compute_module"] or "Unknown",
                "device_count": grp["device_count"],
                "firmware_versions": versions_display,
                "firmware_versions_list": versions_list,
                "is_mixed": len(versions_list) > 1,
                "sample_macs": grp["sample_macs"],
            })
        if groups_list:
            fleet_audit_output[fid] = {"fleet_name": data["fleet_name"], "groups": groups_list}

    unclaimed_rows = [
        {
            "mac_address": d.mac_address,
            "last_seen": d.last_checkin.isoformat() if d.last_checkin else "Unknown",
            "compute_module": d.compute_module or "Unknown",
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
            "versioned_releases":   approved_release_rows,
            "warehouse_tree":       warehouse_tree,
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
            "fleet_tag_suggestions": fleet_tag_suggestions_output,
            "fleet_audit":          fleet_audit_output,
            "unclaimed_devices":    unclaimed_rows,
            "allowed_emails":       allowed_emails,
            "allowed_domains":      allowed_domains,
            "admin_api_tokens":     admin_api_tokens,
            "admin_teams":          admin_teams,
            "admin_users":          admin_users,
            "tag_categories":       TAG_CATEGORIES,
        },
    )
