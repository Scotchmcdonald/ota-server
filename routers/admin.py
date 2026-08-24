import secrets
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from models import User, Team, APIKey, ComputeModule, VersionedRelease, OneShotRelease, UserRole, AllowedEmail, AllowedDomain, Device
from auth import hash_api_key
from database import get_db
from deps import get_current_user, require_admin
from sqlalchemy.orm import Session

router = APIRouter()


# Keep /admin as a redirect for backwards compatibility with bookmarks.
@router.get("/admin", include_in_schema=False)
async def admin_redirect():
    return RedirectResponse(url="/dashboard")


# =============================================================================
# Access Management (Admin-only)
# =============================================================================

@router.post("/admin/access/emails/add")
def access_add_email(
    request: Request,
    email:   str = Form(...),
    note:    str = Form(""),
    db:      Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    email = email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address.")
    if db.query(AllowedEmail).filter(AllowedEmail.email == email).first():
        raise HTTPException(status_code=409, detail="Email already in allowlist.")
    db.add(AllowedEmail(email=email, note=note.strip() or None))
    db.commit()
    return RedirectResponse(url="/dashboard?tab=access", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/access/emails/delete/{entry_id}")
def access_delete_email(
    entry_id: int,
    request:  Request,
    db:       Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    entry = db.query(AllowedEmail).filter(AllowedEmail.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found.")
    # Guard: prevent removing your own entry — would lock yourself out.
    if entry.email == current_user.email:
        raise HTTPException(status_code=400, detail="Cannot remove your own email from the allowlist.")
    db.delete(entry)
    db.commit()
    return RedirectResponse(url="/dashboard?tab=access", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/access/domains/add")
def access_add_domain(
    request: Request,
    domain:  str = Form(...),
    note:    str = Form(""),
    db:      Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    domain = domain.strip().lower().lstrip("@")
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain (e.g. borealtek.ca).")
    if db.query(AllowedDomain).filter(AllowedDomain.domain == domain).first():
        raise HTTPException(status_code=409, detail="Domain already in allowlist.")
    db.add(AllowedDomain(domain=domain, note=note.strip() or None))
    db.commit()
    return RedirectResponse(url="/dashboard?tab=access", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/access/domains/delete/{entry_id}")
def access_delete_domain(
    entry_id: int,
    request:  Request,
    db:       Session = Depends(get_db),
    _current_user: User = Depends(require_admin),
):
    entry = db.query(AllowedDomain).filter(AllowedDomain.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found.")
    db.delete(entry)
    db.commit()
    return RedirectResponse(url="/dashboard?tab=access", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Team Management (Admin-only)
# =============================================================================

@router.post("/admin/teams/add")
def admin_add_team(
    team_name: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    name = team_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Team name is required.")
    if db.query(Team).filter(Team.name == name).first():
        raise HTTPException(status_code=409, detail="Team already exists.")
    db.add(Team(name=name))
    db.commit()
    return RedirectResponse(url="/dashboard?top=settings&sub=teams", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/teams/assign")
def admin_assign_team(
    email: str = Form(...),
    team_name: Optional[str] = Form(None),
    team_id: Optional[int] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
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

    return RedirectResponse(url="/dashboard?top=settings&sub=teams", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/teams/members/remove")
def admin_remove_user_from_team(
    team_id: int = Form(...),
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
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

    return RedirectResponse(url="/dashboard?top=settings&sub=teams", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/teams/delete/{team_id}")
def admin_delete_team(
    team_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    team = db.query(Team).filter(Team.id == team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found.")

    db.delete(team)
    db.commit()
    return RedirectResponse(url="/dashboard?top=settings&sub=teams", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Compute Module Management (Admin-only)
# =============================================================================

@router.post("/admin/compute-modules/add")
def admin_add_compute_module(
    name: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    normalized = name.strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="Compute module name is required.")
    if db.query(ComputeModule).filter(ComputeModule.name == normalized).first():
        raise HTTPException(status_code=409, detail="Compute module already exists.")
    db.add(ComputeModule(name=normalized))
    db.commit()
    return RedirectResponse(url="/dashboard?top=settings&sub=fleets", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/compute-modules/delete/{module_id}")
def admin_delete_compute_module(
    module_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    _ = current_user
    module = db.query(ComputeModule).filter(ComputeModule.id == module_id).first()
    if not module:
        raise HTTPException(status_code=404, detail="Compute module not found.")

    in_use_by_device = db.query(Device.id).filter(Device.compute_module == module.name).first()
    in_use_by_versioned = db.query(VersionedRelease.id).filter(VersionedRelease.compute_module == module.name).first()
    in_use_by_oneshot = db.query(OneShotRelease.id).filter(OneShotRelease.compute_module == module.name).first()
    if in_use_by_device or in_use_by_versioned or in_use_by_oneshot:
        raise HTTPException(
            status_code=400,
            detail="Compute module is actively enrolled by one or more devices or releases and cannot be removed.",
        )

    db.delete(module)
    db.commit()
    return RedirectResponse(url="/dashboard?top=settings&sub=fleets", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# API Key Management (OAuth-protected)
# =============================================================================

@router.post("/api/tokens/generate")
@router.post("/admin/tokens/generate")
@router.post("/admin/generate-key")
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

    token_row = APIKey(
        key_hash=hash_api_key(raw_key),
        key_suffix=raw_key[-8:],
        label=token_label,
        owner_id=current_user.id,
        user_id=current_user.id,
    )
    db.add(token_row)
    db.flush()
    db.commit()

    request.session["new_key_flash"] = raw_key
    request.session["new_key_token_id_flash"] = token_row.id
    return RedirectResponse(url="/dashboard?tab=tokens", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/api/tokens/revoke/{key_id}")
@router.post("/admin/tokens/revoke/{key_id}")
@router.post("/admin/delete-key/{key_id}")
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
