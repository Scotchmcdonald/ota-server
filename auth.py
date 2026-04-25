import hashlib
import os
import secrets
from typing import Optional

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from models import APIKey, User

# =============================================================================
# Google OAuth Configuration
# =============================================================================

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "PASTE_YOUR_GOOGLE_CLIENT_ID_HERE")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "PASTE_YOUR_GOOGLE_CLIENT_SECRET_HERE")

oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# =============================================================================
# Dependencies
# =============================================================================

def hash_api_key(raw_key: str) -> str:
    """One-way SHA-256 hash of a raw API key token for safe database storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()

def get_current_user_from_db(request: Request, db: Session) -> User:
    """Helper to fetch the current user ORM object from the database."""
    session_user = request.session.get("user")
    if not session_user:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please visit /login.",
        )
    
    user = db.query(User).filter(User.email == session_user.get("email")).first()
    if not user:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found in database.",
        )
    return user

def require_admin(request: Request, db: Session) -> User:
    user = get_current_user_from_db(request, db)
    if user.role != "Admin":
         raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin privileges required.",
        )
    return user

def verify_api_key(
    x_admin_key: str = Header(..., description="Machine API key — set as X-Admin-Key header"),
    db: Session = Depends() # Needs to be passed explicitly where used
) -> APIKey:
    """
    FastAPI dependency for machine-to-machine endpoints.
    Hashes the incoming X-Admin-Key header and looks it up in the database.
    """
    key_hash = hash_api_key(x_admin_key)
    api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return api_key

from typing import List, Tuple
from fastapi import Form
from models import ScopeType

# RBAC Logic
def get_current_user_scopes(user: User) -> List[Tuple[ScopeType, int]]:
    """
    Calculates the allowed scopes for a given user.
    Returns a list of tuples in the format: [(ScopeType.Personal, user.id), (ScopeType.Team, team.id)]
    """
    scopes = [(ScopeType.Personal, user.id)]
    for team in user.teams:
        scopes.append((ScopeType.Team, team.id))
    return scopes

def verify_api_key_scope_access(
    scope_type: ScopeType = Form(...),
    target_id: int = Form(...),
    api_key: APIKey = Depends(verify_api_key)
) -> User:
    """
    Verifies the owner of the API Key has explicit rights to write to the requested scope_type & target_id.
    """
    user = api_key.owner
    if user.role.value == "Admin": 
        return user
        
    allowed_scopes = get_current_user_scopes(user=user)
    if (scope_type, target_id) not in allowed_scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The API Key owner does not have explicit access to this scope."
        )
    return user