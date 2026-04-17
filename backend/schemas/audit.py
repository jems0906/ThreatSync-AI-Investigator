from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class AuditEventResponse(BaseModel):
    id: int
    actor: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    status: str
    details: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}
