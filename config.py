import os
import secrets

SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", secrets.token_urlsafe(32))
GOOGLE_OAUTH_REDIRECT_URI = os.getenv("GOOGLE_OAUTH_REDIRECT_URI")
# Comma-separated allowlist used ONLY to seed the database on first run.
ADMIN_EMAILS = set(e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip())
