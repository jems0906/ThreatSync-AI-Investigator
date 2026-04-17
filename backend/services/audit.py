from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AuditEvent


async def log_audit_event(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    status: str,
    details: dict | None = None,
) -> None:
    event = AuditEvent(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        details=details or {},
    )
    db.add(event)
