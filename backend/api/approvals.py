from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.security import require_analyst_auth
from db.database import get_db
from db.models import Alert, AlertStatus, ApprovalRequest, ApprovalStatus, Investigation
from schemas.investigation import ApprovalAction, ApprovalResponse
from services.audit import log_audit_event
from services.cache import cache_service

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


@router.get("/pending", response_model=list[ApprovalResponse])
async def get_pending_approvals(
    _: None = Depends(require_analyst_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ApprovalRequest)
        .where(ApprovalRequest.status == ApprovalStatus.PENDING)
        .order_by(ApprovalRequest.created_at.asc())
    )
    return result.scalars().all()


@router.get("/{investigation_id}", response_model=ApprovalResponse)
async def get_approval(
    investigation_id: int,
    _: None = Depends(require_analyst_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.investigation_id == investigation_id
        )
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return approval


@router.post("/{investigation_id}/approve", response_model=ApprovalResponse)
async def approve_investigation(
    investigation_id: int,
    action: ApprovalAction,
    _: None = Depends(require_analyst_auth),
    db: AsyncSession = Depends(get_db),
):
    approval = await _get_pending_approval(db, investigation_id)
    now = datetime.now(timezone.utc)

    await db.execute(
        update(ApprovalRequest)
        .where(ApprovalRequest.investigation_id == investigation_id)
        .values(
            status=ApprovalStatus.APPROVED,
            analyst_id=action.analyst_id,
            analyst_notes=action.notes,
            decided_at=now,
        )
    )

    # Close the parent alert
    inv_result = await db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    )
    inv = inv_result.scalar_one_or_none()
    if inv:
        await db.execute(
            update(Alert)
            .where(Alert.id == inv.alert_id)
            .values(status=AlertStatus.CLOSED)
        )

    await log_audit_event(
        db,
        actor=action.analyst_id,
        action="approval_approved",
        resource_type="investigation",
        resource_id=str(investigation_id),
        status="success",
        details={"notes": action.notes},
    )

    await db.commit()
    await db.refresh(approval)
    await cache_service.decrement_pending_approvals()
    return approval


@router.post("/{investigation_id}/reject", response_model=ApprovalResponse)
async def reject_investigation(
    investigation_id: int,
    action: ApprovalAction,
    _: None = Depends(require_analyst_auth),
    db: AsyncSession = Depends(get_db),
):
    approval = await _get_pending_approval(db, investigation_id)
    now = datetime.now(timezone.utc)

    await db.execute(
        update(ApprovalRequest)
        .where(ApprovalRequest.investigation_id == investigation_id)
        .values(
            status=ApprovalStatus.REJECTED,
            analyst_id=action.analyst_id,
            analyst_notes=action.notes,
            decided_at=now,
        )
    )

    await log_audit_event(
        db,
        actor=action.analyst_id,
        action="approval_rejected",
        resource_type="investigation",
        resource_id=str(investigation_id),
        status="success",
        details={"notes": action.notes},
    )

    await db.commit()
    await db.refresh(approval)
    await cache_service.decrement_pending_approvals()
    return approval


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_pending_approval(
    db: AsyncSession, investigation_id: int
) -> ApprovalRequest:
    result = await db.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.investigation_id == investigation_id
        )
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if approval.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Approval already {approval.status}. No further action required.",
        )
    return approval
