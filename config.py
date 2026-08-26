import os
import secrets

SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", secrets.token_urlsafe(32))
GOOGLE_OAUTH_REDIRECT_URI = os.getenv("GOOGLE_OAUTH_REDIRECT_URI")
# Comma-separated allowlist used ONLY to seed the database on first run.
ADMIN_EMAILS = set(e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip())

# IANA zone name (e.g. "America/Winnipeg") used ONLY to evaluate Fleet
# AFTER_HOURS windows - deliberately separate from the container's own
# system time (Docker defaults to UTC regardless of where the operator
# actually is) and from every other timestamp in this app, which stays
# UTC internally (last_checkin, upload_timestamp, etc.) regardless of this
# setting.
AFTER_HOURS_TZ = os.getenv("AFTER_HOURS_TZ", "UTC")
