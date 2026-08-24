import re
from datetime import datetime
from typing import Optional, Tuple

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from models import User, Team, APIKey, ScopeType, UserRole, AllowedEmail, AllowedDomain
from auth import hash_api_key, get_current_user_from_db, get_current_user_scopes
from database import get_db


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


def require_admin(
    request: Request,
    db: Session = Depends(get_db),
    x_admin_key: Optional[str] = Header(default=None),
) -> User:
    """
    Requires an authenticated Admin user.
    Supports both session auth and API key auth via X-Admin-Key header.
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
    user = get_current_user(request, db, request.headers.get("Authorization"))
    if user.role != UserRole.Admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin privileges required.",
        )
    return user


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


def has_scope_permission(user: User, scope_type: ScopeType, scope_id: int) -> bool:
    """Check if user has access to the given scope type and ID."""
    if user.role == UserRole.Admin:
        return True
    return (scope_type, scope_id) in get_current_user_scopes(user=user)


def _is_email_allowed(email: str, db: Session) -> bool:
    """Check if a normalized (lowercase) email is permitted by the DB allowlist."""
    if db.query(AllowedEmail).filter(AllowedEmail.email == email).first():
        return True
    domain = email.split("@")[-1] if "@" in email else ""
    if domain and db.query(AllowedDomain).filter(AllowedDomain.domain == domain).first():
        return True
    return False
