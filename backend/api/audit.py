from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.security import require_analyst_auth
from db.database import get_db
from db.models import AuditEvent
from schemas.audit import AuditEventResponse

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditEventResponse])
async def list_audit_events(
    skip: int = 0,
    limit: int = 100,
    action: str | None = None,
    actor: str | None = None,
    _: None = Depends(require_analyst_auth),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc())
    if action:
        query = query.where(AuditEvent.action == action)
    if actor:
        query = query.where(AuditEvent.actor == actor)

    result = await db.execute(query.offset(skip).limit(min(limit, 500)))
    return result.scalars().all()
