from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table, Enum, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship
import enum

Base = declarative_base()

# =============================================================================
# Enums
# =============================================================================

class UserRole(enum.Enum):
    Admin = "Admin"
    User = "User"

class ScopeType(enum.Enum):
    Personal = "Personal"
    Team = "Team"

class ReleaseStatus(enum.Enum):
    Staging = "Staging"    # Uploaded, unversioned, awaiting admin approval or rejection.
    Approved = "Approved"  # Has a real version, eligible for normal fleet resolution.
    Rejected = "Rejected"  # Kept for history/audit; never served or listed as active.

class UpdateMode(enum.Enum):
    LATEST = "LATEST"  # Device/Fleet always tracks the newest matching release.
    FIXED = "FIXED"    # Device/Fleet targets one specific firmware name + version.

# =============================================================================
# Association Tables
# =============================================================================

user_team_association = Table(
    "user_team",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("team_id", Integer, ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
)

# Junction tables for tags use indexed FK columns rather than a JSON column so
# SQLite can efficiently answer subset-match and exact-match tag comparisons.
device_tag_association = Table(
    "device_tag",
    Base.metadata,
    Column("device_id", Integer, ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)
)

fleet_tag_association = Table(
    "fleet_tag",
    Base.metadata,
    Column("fleet_id", Integer, ForeignKey("fleets.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)
)

versioned_release_tag_association = Table(
    "versioned_release_tag",
    Base.metadata,
    Column("release_id", Integer, ForeignKey("versioned_releases.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)
)

# =============================================================================
# Core Entities
# =============================================================================

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=True)
    role = Column(Enum(UserRole), default=UserRole.User, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    api_tokens = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    teams = relationship("Team", secondary=user_team_association, back_populates="members")

class Team(Base):
    __tablename__ = "teams"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    members = relationship("User", secondary=user_team_association, back_populates="teams")

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, nullable=False, index=True)
    key_suffix = Column(String(8), nullable=True)
    label = Column(String, nullable=True)
    # Legacy compatibility: some deployed DBs still enforce owner_id NOT NULL.
    owner_id = Column(Integer, nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    
    user = relationship("User", back_populates="api_tokens")

class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (
        UniqueConstraint("category", "name", name="uq_tag_category_name"),
    )
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    category = Column(String, nullable=False, default="custom")
    color = Column(String, nullable=False, default="#3b82f6")

    # Relationships
    devices = relationship("Device", secondary=device_tag_association, back_populates="tags")
    fleets = relationship("Fleet", secondary=fleet_tag_association, back_populates="tags")
    versioned_releases = relationship("VersionedRelease", secondary=versioned_release_tag_association, back_populates="tags")

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String, unique=True, index=True, nullable=False)
    nickname = Column(String, nullable=True)
    secret = Column(String, nullable=False)
    battery = Column(Integer, nullable=True)
    last_checkin = Column(DateTime, default=datetime.utcnow)
    last_ota_status = Column(String)

    # Currently-installed firmware version, self-reported by the device on
    # every check-in. Used for dashboard display and fleet audit history.
    current_firmware_version = Column(String, nullable=True)
    
    # Ownership & Claiming
    claimed = Column(Boolean, default=False, nullable=False)
    scope_id = Column(Integer, nullable=True, index=True)
    scope_type = Column(Enum(ScopeType), nullable=True, index=True)

    # Fleet assignment (standalone when NULL, or belongs to one Fleet).
    fleet_id = Column(Integer, ForeignKey("fleets.id", ondelete="SET NULL"), nullable=True, index=True)

    # Compute module (ESP hardware type, e.g. S2/S3/C2).
    compute_module = Column(String, nullable=True)

    # OTA update mode and target resolution.
    update_mode = Column(Enum(UpdateMode), default=UpdateMode.LATEST, nullable=False)
    target_firmware_name = Column(String, nullable=True)
    target_firmware_version = Column(String, nullable=True)

    # Heartbeat polling interval in seconds (default 60).
    heartbeat_interval = Column(Integer, default=60, nullable=False)

    # Direct assignment to a One-Shot release; used alongside versioned-release
    # targeting to let a standalone device pin to either release tier.
    target_oneshot_release_id = Column(Integer, ForeignKey("one_shot_releases.id", ondelete="SET NULL"), nullable=True, index=True)

    # Relationships
    fleet = relationship("Fleet", back_populates="devices")
    tags = relationship("Tag", secondary=device_tag_association, back_populates="devices")
    target_oneshot_release = relationship("OneShotRelease", foreign_keys=[target_oneshot_release_id])

class Fleet(Base):
    __tablename__ = "fleets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)

    # OTA update mode and target resolution (same semantics as Device).
    update_mode = Column(Enum(UpdateMode), default=UpdateMode.LATEST, nullable=False)
    target_firmware_name = Column(String, nullable=True)
    target_firmware_version = Column(String, nullable=True)

    # Direct assignment to a One-Shot release (same reason as on Device).
    target_oneshot_release_id = Column(Integer, ForeignKey("one_shot_releases.id", ondelete="SET NULL"), nullable=True)

    # Ownership scoping (consistent with Device's scope_id/scope_type pattern).
    scope_id = Column(Integer, nullable=True, index=True)
    scope_type = Column(Enum(ScopeType), nullable=True, index=True)

    # Relationships
    devices = relationship("Device", back_populates="fleet")
    tags = relationship("Tag", secondary=fleet_tag_association, back_populates="fleets")

# =============================================================================
# Firmware Models (Versioned & One-Shot)
# =============================================================================

class VersionedRelease(Base):
    """
    A versioned firmware binary with approval lifecycle and tag-based resolution.
    """
    __tablename__ = "versioned_releases"
    __table_args__ = (
        UniqueConstraint("firmware_name", "firmware_version", "compute_module", name="uq_versioned_release_target"),
    )

    id = Column(Integer, primary_key=True, index=True)
    firmware_name = Column(String, nullable=False, index=True)
    firmware_version = Column(String, nullable=True, index=True)
    status = Column(Enum(ReleaseStatus), default=ReleaseStatus.Staging, nullable=False, index=True)
    file_path = Column(String, nullable=False)
    compute_module = Column(String, nullable=False, index=True)
    upload_timestamp = Column(DateTime, default=datetime.utcnow)

    tags = relationship("Tag", secondary=versioned_release_tag_association, back_populates="versioned_releases")


class OneShotRelease(Base):
    """
    A rapid-prototyping firmware upload with no SemVer or approval lifecycle.
    Searchable only by upload date and ESP compute module type.
    """
    __tablename__ = "one_shot_releases"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    upload_date = Column(DateTime, default=datetime.utcnow)
    compute_module = Column(String, nullable=False, index=True)
    notes = Column(String, nullable=True)

    # Ownership scoping (mirrored from the old Firmware class).
    scope_id = Column(Integer, nullable=True, index=True)
    scope_type = Column(Enum(ScopeType), nullable=True, index=True)

# =============================================================================
# Access Control
# =============================================================================

class AllowedEmail(Base):
    __tablename__ = "allowed_emails"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AllowedDomain(Base):
    __tablename__ = "allowed_domains"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, nullable=False, index=True)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ComputeModule(Base):
    """
    A managed list of ESP32 compute module architectures (e.g. ESP32-S3-WROOM-1).
    Populated automatically from firmware uploads and managed manually by admins.
    Removal is blocked if any device or firmware release references the value.
    """
    __tablename__ = "compute_modules"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
