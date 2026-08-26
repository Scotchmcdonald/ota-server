import re
import secrets
from typing import Optional

from fastapi import HTTPException
from models import ComputeModule, Device, Tag
from sqlalchemy.orm import Session
from packaging.version import parse as parse_version

TAG_CATEGORIES = {
    "hardware": "Device hardware characteristics (chip, devboard, carrier)",
    "firmware_compat": "Firmware compatibility declarations",
    "firmware_feature": "Firmware capability declarations",
    "firmware_build": "Build type (production, debug, canary)",
    "role": "Group routing and role tags",
}

# The full real Espressif ESP32 chip-family lineup - not board/prototyping-
# surface descriptors (those aren't "ESP32 Hardware Type" and vary per
# project; admins tag those separately if/when they need to).
DEFAULT_HARDWARE_TAGS = [
    ("h1", "ESP32", "#0ea5e9"),
    ("h2", "ESP32-S2", "#0891b2"),
    ("h3", "ESP32-S3", "#06b6d4"),
    ("h4", "ESP32-C2", "#22d3ee"),
    ("h5", "ESP32-C3", "#67e8f9"),
    ("h6", "ESP32-C6", "#38bdf8"),
    ("h7", "ESP32-H2", "#0284c7"),
    ("h8", "ESP32-P4", "#0369a1"),
]


def _parse_optional_int(value: Optional[str], field_name: str) -> Optional[int]:
    if value is None:
        return None
    cleaned = value.strip()
    if cleaned == "":
        return None
    try:
        return int(cleaned)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}.")


def _resolve_compute_module_name(raw_value: str, db: Session) -> str:
    cleaned = (raw_value or "").strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="Missing compute_module.")

    if cleaned.isdigit():
        module = db.query(ComputeModule).filter(ComputeModule.id == int(cleaned)).first()
        if not module:
            raise HTTPException(status_code=400, detail="Unknown compute_module id.")
        return module.name

    return cleaned


def _upsert_tags_for_device(device: Device, tags_csv: str, db: Session, actor_is_admin: bool = False) -> None:
    """
    Assign tags to a device. Non-admin users can only create tags under the
    'custom' category. OTA-relevant categories ('hardware', 'firmware_compat',
    'firmware_feature', 'firmware_build') require admin privileges.
    """
    parsed_tags = [t.strip() for t in (tags_csv or "").split(",") if t.strip()]
    if not parsed_tags:
        device.tags = []
        return

    existing = db.query(Tag).filter(Tag.name.in_(parsed_tags)).all()
    existing_by_name = {t.name: t for t in existing}
    resolved_tags = []

    for name in parsed_tags:
        tag = existing_by_name.get(name)
        if not tag:
            category = "custom"
            if actor_is_admin:
                pass
            tag = Tag(name=name, category=category, color="#3b82f6")
            db.add(tag)
            existing_by_name[name] = tag
        resolved_tags.append(tag)

    device.tags = resolved_tags


def is_newer_version(v1: str, v2: str) -> bool:
    """Returns True if v1 is semantically newer than v2."""
    try:
        return parse_version(v1) > parse_version(v2)
    except Exception:
        return False


def _sanitize_field(value: str, allow_dots: bool = False) -> str:
    """Strip characters that could enable path traversal or injection."""
    pattern = r"[^a-zA-Z0-9_\-\.]" if allow_dots else r"[^a-zA-Z0-9_\-]"
    return re.sub(pattern, "", value)


def _normalize_firmware_name(value: Optional[str]) -> str:
    return (value or "").strip()


def _normalize_firmware_version(value: Optional[str]) -> str:
    return (value or "").strip()


def _effective_device_tags(device: Device) -> set:
    """
    A device's effective tag set for matching purposes: its own tags plus
    its fleet's tags, unioned. This is computed at read-time, never
    persisted - a device's own tags never change when it moves fleets, and
    the fleet's contribution updates automatically the moment fleet_id
    changes, with no sync/cascade logic needed anywhere.
    """
    own = {t.name for t in (device.tags or [])}
    fleet_tags = {t.name for t in (device.fleet.tags or [])} if device.fleet else set()
    return own | fleet_tags


def _tag_gap(required_tag_names: set, actual_tag_names: set) -> dict:
    """Compute missing/extra tags between a target (required) and a source (actual)."""
    missing_tags = sorted(required_tag_names - actual_tag_names)
    extra_tags = sorted(actual_tag_names - required_tag_names)
    subset_match = len(missing_tags) == 0
    exact_match = subset_match and len(extra_tags) == 0
    return {
        "subset_match": subset_match,
        "exact_match": exact_match,
        "missing_tags": missing_tags,
        "extra_tags": extra_tags,
    }
