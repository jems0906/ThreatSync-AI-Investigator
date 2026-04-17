from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.security import require_service_auth
from db.database import get_db
from db.models import Investigation
from schemas.investigation import InvestigationResponse

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


@router.get("", response_model=list[InvestigationResponse])
async def list_investigations(
    skip: int = 0,
    limit: int = 50,
    _: None = Depends(require_service_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Investigation)
        .order_by(Investigation.created_at.desc())
        .offset(skip)
        .limit(min(limit, 200))
    )
    return result.scalars().all()


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: int,
    _: None = Depends(require_service_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.get("/alert/{alert_id}", response_model=list[InvestigationResponse])
async def get_investigations_for_alert(
    alert_id: int,
    _: None = Depends(require_service_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Investigation)
        .where(Investigation.alert_id == alert_id)
        .order_by(Investigation.created_at.desc())
    )
    return result.scalars().all()
