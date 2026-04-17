import json

from fastapi import APIRouter
from fastapi.websockets import WebSocket, WebSocketDisconnect
from sqlalchemy import select, update

from config import settings
from db.database import AsyncSessionLocal
from db.models import (
    Alert,
    AlertStatus,
    ApprovalRequest,
    ApprovalStatus,
    Investigation,
    InvestigationStatus,
)
from services.cache import cache_service
from services.audit import log_audit_event
from services.llm_service import llm_service
from services.rag_pipeline import rag_pipeline

router = APIRouter()


@router.websocket("/ws/investigations/{alert_id}")
async def investigate_alert(websocket: WebSocket, alert_id: int) -> None:
    """
    Full real-time investigation pipeline over WebSocket.

    Message protocol (server → client):
      {"type": "status",              "phase": str, "message": str}
      {"type": "alert_data",          "data": {...}}
      {"type": "investigation_created","investigation_id": int}
      {"type": "context_retrieved",   "data": {...}}
      {"type": "analysis_start"}
      {"type": "token",               "content": str}   ← streamed LLM tokens
      {"type": "analysis_complete",   "investigation_id": int, "data": {...}}
      {"type": "approval_required",   "investigation_id": int, "severity_score": float}
      {"type": "auto_resolved",       "recommendation": str}
      {"type": "error",               "message": str}
    """
    if settings.API_AUTH_ENABLED:
        api_key = websocket.query_params.get("api_key")
        if not api_key or api_key != settings.API_KEY_SERVICE:
            await websocket.close(code=1008)
            return

    await websocket.accept()

    async with AsyncSessionLocal() as db:
        try:
            await _send(websocket, {
                "type": "status",
                "phase": "init",
                "message": "Connection established. Fetching alert…",
            })

            # ── 1. Load alert ─────────────────────────────────────────────
            res = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = res.scalar_one_or_none()
            if not alert:
                await _send(websocket, {
                    "type": "error",
                    "message": f"Alert {alert_id} not found.",
                })
                return

            await _send(websocket, {
                "type": "alert_data",
                "data": _alert_dict(alert),
            })

            # Mark alert as investigating
            await db.execute(
                update(Alert)
                .where(Alert.id == alert_id)
                .values(status=AlertStatus.INVESTIGATING)
            )
            await db.commit()

            # ── 2. Create investigation record ────────────────────────────
            investigation = Investigation(
                alert_id=alert_id,
                status=InvestigationStatus.IN_PROGRESS,
            )
            db.add(investigation)
            await db.commit()
            await db.refresh(investigation)
            investigation_id = investigation.id

            await _send(websocket, {
                "type": "investigation_created",
                "investigation_id": investigation_id,
            })

            # ── 3. RAG retrieval ──────────────────────────────────────────
            await _send(websocket, {
                "type": "status",
                "phase": "rag",
                "message": "Retrieving contextual intelligence via RAG pipeline…",
            })

            context = await rag_pipeline.retrieve_context(
                alert_type=alert.alert_type,
                user_id=alert.user_id,
                raw_data=alert.raw_data,
            )

            await _send(websocket, {
                "type": "context_retrieved",
                "data": {
                    "threat_intel_docs": len(context.get("threat_intel", [])),
                    "user_activity_docs": len(context.get("user_activity", [])),
                    "similar_alert_docs": len(context.get("similar_alerts", [])),
                    "user_activity_preview": [
                        d["content"] for d in context.get("user_activity", [])[:3]
                    ],
                    "threat_intel_preview": [
                        d["content"][:200] for d in context.get("threat_intel", [])[:2]
                    ],
                },
            })

            # ── 4. LLM streaming analysis ─────────────────────────────────
            await _send(websocket, {"type": "analysis_start"})

            full_response = ""
            async for token in llm_service.investigate_stream(
                alert=alert, context=context
            ):
                full_response += token
                await _send(websocket, {"type": "token", "content": token})

            # ── 5. Parse structured result ────────────────────────────────
            result_data = _extract_json(full_response)
            if result_data is None:
                await _send(websocket, {
                    "type": "error",
                    "message": "LLM did not return valid JSON. Raw response stored.",
                })
                await db.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(
                        status=InvestigationStatus.FAILED,
                        raw_analysis=full_response,
                    )
                )
                await db.commit()
                return

            severity_score = float(result_data.get("severity_score", 5.0))

            # ── 6. Persist investigation ──────────────────────────────────
            await db.execute(
                update(Investigation)
                .where(Investigation.id == investigation_id)
                .values(
                    threat_type=result_data.get("threat_type"),
                    severity_score=severity_score,
                    confidence=float(result_data.get("confidence", 0.5)),
                    summary=result_data.get("summary"),
                    key_findings=result_data.get("key_findings", []),
                    investigation_steps=result_data.get("investigation_steps", []),
                    iocs=result_data.get("iocs", []),
                    mitre_tactics=result_data.get("mitre_tactics", []),
                    recommendation=result_data.get("recommendation"),
                    estimated_risk=result_data.get("estimated_risk"),
                    raw_analysis=full_response,
                    status=InvestigationStatus.COMPLETED,
                )
            )
            await db.execute(
                update(Alert)
                .where(Alert.id == alert_id)
                .values(status=AlertStatus.INVESTIGATED)
            )
            await log_audit_event(
                db,
                actor="ai-investigator",
                action="investigation_completed",
                resource_type="investigation",
                resource_id=str(investigation_id),
                status="success",
                details={
                    "alert_id": alert_id,
                    "severity_score": severity_score,
                    "recommendation": result_data.get("recommendation"),
                },
            )
            await db.commit()

            await _send(websocket, {
                "type": "analysis_complete",
                "investigation_id": investigation_id,
                "data": result_data,
            })

            # Store in RAG for future similarity lookups
            await rag_pipeline.store_investigation(
                alert=_alert_dict(alert), investigation=result_data
            )

            # ── 7. Approval or auto-resolve ───────────────────────────────
            if severity_score >= settings.APPROVAL_THRESHOLD:
                approval = ApprovalRequest(
                    investigation_id=investigation_id,
                    status=ApprovalStatus.PENDING,
                )
                db.add(approval)
                await log_audit_event(
                    db,
                    actor="ai-investigator",
                    action="approval_requested",
                    resource_type="investigation",
                    resource_id=str(investigation_id),
                    status="success",
                    details={"severity_score": severity_score},
                )
                await db.commit()
                await cache_service.increment_pending_approvals()

                await _send(websocket, {
                    "type": "approval_required",
                    "investigation_id": investigation_id,
                    "severity_score": severity_score,
                    "message": (
                        f"Severity {severity_score:.1f}/10 — escalated for "
                        "analyst review."
                    ),
                })
            else:
                if result_data.get("recommendation") == "ignore":
                    await db.execute(
                        update(Alert)
                        .where(Alert.id == alert_id)
                        .values(status=AlertStatus.CLOSED)
                    )
                    await db.commit()

                await log_audit_event(
                    db,
                    actor="ai-investigator",
                    action="auto_resolution",
                    resource_type="investigation",
                    resource_id=str(investigation_id),
                    status="success",
                    details={
                        "severity_score": severity_score,
                        "recommendation": result_data.get("recommendation"),
                    },
                )
                await db.commit()

                await _send(websocket, {
                    "type": "auto_resolved",
                    "recommendation": result_data.get("recommendation"),
                    "message": (
                        f"Severity {severity_score:.1f}/10 — no manual approval "
                        "required."
                    ),
                })

            # Cache result
            await cache_service.cache_investigation(investigation_id, result_data)

        except WebSocketDisconnect:
            pass
        except Exception as exc:
            try:
                await _send(websocket, {"type": "error", "message": str(exc)})
            except Exception:
                pass


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _send(ws: WebSocket, data: dict) -> None:
    await ws.send_text(json.dumps(data, default=str))


def _alert_dict(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "alert_uuid": alert.alert_uuid,
        "alert_type": alert.alert_type,
        "user_id": alert.user_id,
        "source_ip": alert.source_ip,
        "hostname": alert.hostname,
        "severity_hint": alert.severity_hint,
        "raw_data": alert.raw_data,
        "status": alert.status,
        "occurred_at": alert.occurred_at.isoformat() if alert.occurred_at else None,
    }


def _extract_json(text: str) -> dict | None:
    """Locate and parse the first top-level JSON object in an LLM response."""
    start = text.find("{")
    end = text.rfind("}") + 1
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return None
