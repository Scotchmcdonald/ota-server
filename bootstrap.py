from utils import TAG_CATEGORIES, DEFAULT_HARDWARE_TAGS, DEFAULT_BUILD_TAGS
from config import ADMIN_EMAILS
from database import SessionLocal
from models import Tag, User, UserRole, AllowedEmail


def _seed_tag_categories() -> None:
    """
    Ensure tag categories and default tags exist in the database.
    Runs on every startup; idempotent.
    """
    db = SessionLocal()
    try:
        for category, description in TAG_CATEGORIES.items():
            pass  # Categories are validated at the application level; no row needed.

        for key, name, color in DEFAULT_HARDWARE_TAGS:
            existing = db.query(Tag).filter(
                Tag.category == "hardware",
                Tag.name == name,
            ).first()
            if not existing:
                db.add(Tag(name=name, category="hardware", color=color))

        for key, name, color in DEFAULT_BUILD_TAGS:
            existing = db.query(Tag).filter(
                Tag.category == "firmware_build",
                Tag.name == name,
            ).first()
            if not existing:
                db.add(Tag(name=name, category="firmware_build", color=color))

        db.commit()
    finally:
        db.close()


def _seed_allowlist_from_env():
    """
    On startup:
    1) inject any emails from ADMIN_EMAILS into the allowlist table, and
    2) reconcile existing users so listed emails are Admin.

    This prevents role drift when ADMIN_EMAILS changes after users were
    already created in earlier deployments.
    """
    if not ADMIN_EMAILS:
        return
    db = SessionLocal()
    try:
        for email in ADMIN_EMAILS:
            if not db.query(AllowedEmail).filter(AllowedEmail.email == email).first():
                db.add(AllowedEmail(email=email, note="Seeded from ADMIN_EMAILS env var"))
            user = db.query(User).filter(User.email == email).first()
            if user and user.role != UserRole.Admin:
                user.role = UserRole.Admin
        db.commit()
    finally:
        db.close()
