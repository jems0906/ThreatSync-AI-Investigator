import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.security import require_service_auth
from db.database import get_db
from db.models import Alert, AlertStatus
from schemas.alert import AlertCreate, AlertResponse
from services.audit import log_audit_event
from services.cache import cache_service

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    skip: int = 0,
    limit: int = 50,
    status: str | None = None,
    alert_type: str | None = None,
    _: None = Depends(require_service_auth),
    db: AsyncSession = Depends(get_db),
):
    query = select(Alert).order_by(Alert.created_at.desc())
    if status:
        query = query.where(Alert.status == status)
    if alert_type:
        query = query.where(Alert.alert_type == alert_type)
    query = query.offset(skip).limit(min(limit, 200))
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=AlertResponse, status_code=201)
async def ingest_alert(
    payload: AlertCreate,
    _: None = Depends(require_service_auth),
    db: AsyncSession = Depends(get_db),
):
    alert = Alert(
        alert_uuid=str(uuid.uuid4()),
        alert_type=payload.alert_type.value,
        user_id=payload.user_id,
        source_ip=payload.source_ip,
        hostname=payload.hostname,
        severity_hint=payload.severity_hint,
        raw_data=payload.raw_data,
        status=AlertStatus.NEW,
        occurred_at=payload.occurred_at,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    await log_audit_event(
        db,
        actor="service",
        action="alert_ingested",
        resource_type="alert",
        resource_id=str(alert.id),
        status="success",
        details={
            "alert_type": alert.alert_type,
            "user_id": alert.user_id,
            "source_ip": alert.source_ip,
        },
    )
    await db.commit()

    # Cache summary in Redis (non-fatal)
    await cache_service.push_alert(
        {
            "id": alert.id,
            "alert_uuid": alert.alert_uuid,
            "alert_type": alert.alert_type,
            "user_id": alert.user_id,
            "source_ip": alert.source_ip,
            "severity_hint": alert.severity_hint,
            "status": alert.status,
            "occurred_at": alert.occurred_at.isoformat() if alert.occurred_at else None,
        }
    )
    return alert


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    _: None = Depends(require_service_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/seed", status_code=201)
async def seed_mock_alerts(
    _: None = Depends(require_service_auth),
    db: AsyncSession = Depends(get_db),
):
    """Developer endpoint — seed mock SOC alerts."""
    from mock_data.seed import seed_alerts

    count = await seed_alerts(db)
    await log_audit_event(
        db,
        actor="service",
        action="alerts_seeded",
        resource_type="alert",
        resource_id=None,
        status="success",
        details={"count": count},
    )
    await db.commit()
    return {"message": f"Seeded {count} mock alerts."}
