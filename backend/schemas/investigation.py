from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class InvestigationStep(BaseModel):
    step: int
    action: str
    rationale: str


class InvestigationResult(BaseModel):
    threat_type: str
    severity_score: float = Field(ge=1, le=10)
    confidence: float = Field(ge=0, le=1)
    summary: str
    key_findings: list[str]
    investigation_steps: list[InvestigationStep]
    iocs: list[str]
    mitre_tactics: list[str]
    recommendation: str   # escalate | monitor | ignore
    estimated_risk: str   # critical | high | medium | low


class InvestigationResponse(BaseModel):
    id: int
    alert_id: int
    threat_type: Optional[str] = None
    severity_score: Optional[float] = None
    confidence: Optional[float] = None
    summary: Optional[str] = None
    key_findings: Optional[list] = None
    investigation_steps: Optional[list] = None
    iocs: Optional[list] = None
    mitre_tactics: Optional[list] = None
    recommendation: Optional[str] = None
    estimated_risk: Optional[str] = None
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ApprovalAction(BaseModel):
    analyst_id: str
    notes: Optional[str] = None


class ApprovalResponse(BaseModel):
    id: int
    investigation_id: int
    status: str
    analyst_id: Optional[str] = None
    analyst_notes: Optional[str] = None
    decided_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}
