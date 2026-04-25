from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Table, Enum, UniqueConstraint
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

# =============================================================================
# Association Tables
# =============================================================================

user_team_association = Table(
    "user_team",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("team_id", Integer, ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
)

device_label_association = Table(
    "device_label",
    Base.metadata,
    Column("device_id", Integer, ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True),
    Column("label_id", Integer, ForeignKey("labels.id", ondelete="CASCADE"), primary_key=True)
)

firmware_label_association = Table(
    "firmware_label",
    Base.metadata,
    Column("firmware_id", Integer, ForeignKey("firmware.id", ondelete="CASCADE"), primary_key=True),
    Column("label_id", Integer, ForeignKey("labels.id", ondelete="CASCADE"), primary_key=True)
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
    
    api_keys = relationship("APIKey", back_populates="owner", cascade="all, delete-orphan")
    teams = relationship("Team", secondary=user_team_association, back_populates="members")

class Team(Base):
    __tablename__ = "teams"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    members = relationship("User", secondary=user_team_association, back_populates="teams")
    application_groups = relationship("ApplicationGroup", back_populates="team", cascade="all, delete-orphan")

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, nullable=False, index=True)
    label = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    owner = relationship("User", back_populates="api_keys")

class Label(Base):
    __tablename__ = "labels"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    color = Column(String, nullable=False, default="#3b82f6")

    # Relationships
    devices = relationship("Device", secondary=device_label_association, back_populates="labels")
    firmwares = relationship("Firmware", secondary=firmware_label_association, back_populates="labels")

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String, unique=True, index=True, nullable=False)
    secret = Column(String, nullable=False)
    device_class = Column(String, index=True, nullable=False)
    version = Column(String)
    battery = Column(Integer, nullable=True)
    last_checkin = Column(DateTime, default=datetime.utcnow)
    last_ota_status = Column(String)
    
    # Ownership & Claiming
    claimed = Column(Boolean, default=False, nullable=False)
    scope_id = Column(Integer, nullable=True, index=True)
    scope_type = Column(Enum(ScopeType), nullable=True, index=True)

    # Cascading OTA Resolution
    device_profile_id = Column(Integer, ForeignKey("device_profiles.id", ondelete="SET NULL"), nullable=True, index=True)
    application_group_id = Column(Integer, ForeignKey("application_groups.id", ondelete="SET NULL"), nullable=True, index=True)
    firmware_override_id = Column(Integer, ForeignKey("firmware_releases.id", ondelete="SET NULL"), nullable=True, index=True)

    labels = relationship("Label", secondary=device_label_association, back_populates="devices")
    device_profile = relationship("DeviceProfile", back_populates="devices", foreign_keys=[device_profile_id])
    application_group = relationship("ApplicationGroup", back_populates="devices", foreign_keys=[application_group_id])
    firmware_override = relationship("FirmwareRelease", foreign_keys=[firmware_override_id])

class Firmware(Base):
    __tablename__ = "firmware"
    id = Column(Integer, primary_key=True, index=True)
    device_class = Column(String, index=True, nullable=False)
    version = Column(String, index=True, nullable=False)
    file_path = Column(String, nullable=False)
    upload_timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Ownership
    scope_id = Column(Integer, nullable=True, index=True)
    scope_type = Column(Enum(ScopeType), nullable=True, index=True)
    
    labels = relationship("Label", secondary=firmware_label_association, back_populates="firmwares")


# =============================================================================
# Hardware Profile & Cascading OTA Models
# =============================================================================

class DeviceProfile(Base):
    """
    Describes a specific hardware variant (chip + peripherals).
    Firmware is bound to a profile at upload time, preventing cross-profile deploys.
    """
    __tablename__ = "device_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)  # e.g. "FeatherS3_EnvSensor"
    tags = Column(JSON, nullable=False, default=list)               # e.g. ["I2C", "BME280", "3.3V"]

    firmware_releases = relationship("FirmwareRelease", back_populates="device_profile")
    devices = relationship("Device", back_populates="device_profile")


class FirmwareRelease(Base):
    """
    A versioned firmware binary rigidly associated with one DeviceProfile.
    This is the authoritative record for any OTA resolution.
    """
    __tablename__ = "firmware_releases"
    __table_args__ = (
        UniqueConstraint("version", "device_profile_id", name="uq_release_version_profile"),
    )

    id = Column(Integer, primary_key=True, index=True)
    version = Column(String, nullable=False, index=True)            # e.g. "v2.3.1"
    file_path = Column(String, nullable=False)
    device_profile_id = Column(Integer, ForeignKey("device_profiles.id"), nullable=False, index=True)
    upload_timestamp = Column(DateTime, default=datetime.utcnow)

    device_profile = relationship("DeviceProfile", back_populates="firmware_releases")
    application_groups = relationship("ApplicationGroup", back_populates="target_release")


class AllowedEmail(Base):
    """
    An explicitly permitted Google account email address.
    Checked at OAuth callback time. Managed at runtime by Admins.
    """
    __tablename__ = "allowed_emails"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)   # Stored lowercase.
    note = Column(String, nullable=True)                               # Optional label, e.g. "Scott - BorealTek"
    created_at = Column(DateTime, default=datetime.utcnow)


class AllowedDomain(Base):
    """
    A wildcard domain rule, e.g. 'borealtek.ca'.
    Any Google account whose email ends in @<domain> is permitted.
    Managed at runtime by Admins.
    """
    __tablename__ = "allowed_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, nullable=False, index=True)  # Stored lowercase, no leading @.
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ApplicationGroup(Base):
    """
    A logical fleet segment owned by a team.
    Defines the production firmware target for all member devices unless
    a device-level firmware_override is set.
    """
    __tablename__ = "application_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)               # e.g. "Outdoor Sensors"
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    # Nullable: a group may exist before any firmware is designated.
    target_release_id = Column(Integer, ForeignKey("firmware_releases.id", ondelete="SET NULL"), nullable=True, index=True)

    team = relationship("Team", back_populates="application_groups")
    target_release = relationship("FirmwareRelease", back_populates="application_groups", foreign_keys=[target_release_id])
    devices = relationship("Device", back_populates="application_group")
