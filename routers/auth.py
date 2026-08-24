from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from auth import oauth
from config import GOOGLE_OAUTH_REDIRECT_URI, ADMIN_EMAILS
from database import get_db
from models import User, UserRole
from deps import _is_email_allowed
from sqlalchemy.orm import Session

router = APIRouter()


@router.get("/login", include_in_schema=False)
async def login(request: Request):
    """Redirect the browser to Google's OAuth 2.0 consent screen."""
    if not GOOGLE_OAUTH_REDIRECT_URI:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GOOGLE_OAUTH_REDIRECT_URI is not configured.",
        )
    return await oauth.google.authorize_redirect(request, GOOGLE_OAUTH_REDIRECT_URI)


@router.get("/auth", name="auth_callback", include_in_schema=False)
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
        # Give admin role if email is in the ADMIN_EMAILS allowlist.
        role = UserRole.Admin if email in ADMIN_EMAILS else UserRole.User
        user = User(email=email, name=user_info.get("name", ""), role=role)
        db.add(user)
        db.commit()
    elif email in ADMIN_EMAILS and user.role != UserRole.Admin:
        # Promote legacy records created before ADMIN_EMAILS included this user.
        user.role = UserRole.Admin
        db.commit()

    request.session["user"] = {"email": email, "name": user_info.get("name", ""), "role": user.role.value}
    return RedirectResponse(url="/dashboard")


@router.get("/logout", include_in_schema=False)
async def logout(request: Request):
    """Clear the session cookie and redirect to /login."""
    request.session.clear()
    return RedirectResponse(url="/login")


# Convenience redirect from root.
@router.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/dashboard")
