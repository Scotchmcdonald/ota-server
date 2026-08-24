from typing import Optional

from pydantic import BaseModel
from models import ScopeType


class AssignTagsRequest(BaseModel):
    tag_ids: list[int]


class DeployPreviewRequest(BaseModel):
    fleet_id: int
    firmware_name: str
    firmware_version: Optional[str] = None
    update_mode: str = "LATEST"


class TeamCreateRequest(BaseModel):
    name: str


class TeamAssignRequest(BaseModel):
    user_email: str
    team_id: int


class ClaimDevicePayload(BaseModel):
    scope_type: ScopeType
    target_id: int
