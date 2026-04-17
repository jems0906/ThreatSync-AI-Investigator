from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertType(str, Enum):
    LOGIN_FAILURE = "login_failure"
    MALWARE_DETECTION = "malware_detection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"


class AlertCreate(BaseModel):
    alert_type: AlertType
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    severity_hint: Optional[str] = None
    raw_data: dict[str, Any]
    occurred_at: datetime


class AlertResponse(BaseModel):
    id: int
    alert_uuid: str
    alert_type: str
    user_id: Optional[str]
    source_ip: Optional[str]
    hostname: Optional[str]
    severity_hint: Optional[str]
    raw_data: dict[str, Any]
    status: str
    occurred_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}
