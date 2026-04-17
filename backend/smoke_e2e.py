import argparse
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from config import settings
from main import app


def service_headers() -> dict[str, str]:
    if not settings.API_AUTH_ENABLED:
        return {}
    return {"X-API-Key": settings.API_KEY_SERVICE}


def analyst_headers() -> dict[str, str]:
    if not settings.API_AUTH_ENABLED:
        return {}
    return {"X-Analyst-Key": settings.API_KEY_ANALYST}


def ensure_alert(client: TestClient) -> int:
    response = client.get(
        "/api/alerts",
        params={"status": "new", "limit": 1},
        headers=service_headers(),
    )
    response.raise_for_status()
    alerts = response.json()
    if alerts:
        return int(alerts[0]["id"])

    payload = {
        "alert_type": "login_failure",
        "user_id": "smoke.test@company.com",
        "source_ip": "185.220.101.47",
        "hostname": None,
        "severity_hint": "high",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "raw_data": {
            "event_type": "multiple_auth_failures",
            "target_service": "vpn.company.com",
            "failure_count": 41,
            "time_window_minutes": 5,
            "geo_location": "Minsk, Belarus",
            "user_agent": "libcurl/7.81.0",
            "attempted_usernames": ["smoke.test", "admin"],
        },
    }
    created = client.post("/api/alerts", json=payload, headers=service_headers())
    created.raise_for_status()
    return int(created.json()["id"])


def run_websocket_flow(client: TestClient, alert_id: int, max_messages: int) -> dict:
    non_token_types: list[str] = []
    token_count = 0
    investigation_id = None
    final_payload = None
    decision_event = None

    ws_path = f"/ws/investigations/{alert_id}"
    if settings.API_AUTH_ENABLED:
        ws_path = f"{ws_path}?api_key={settings.API_KEY_SERVICE}"

    with client.websocket_connect(ws_path) as ws:
        for _ in range(max_messages):
            message = ws.receive_json()
            msg_type = message.get("type")

            if msg_type == "token":
                token_count += 1
            else:
                non_token_types.append(msg_type)

            if msg_type == "investigation_created":
                investigation_id = message.get("investigation_id")

            if msg_type == "analysis_complete":
                final_payload = message.get("data", {})

            if msg_type in ("approval_required", "auto_resolved"):
                decision_event = msg_type
                break

    required_types = [
        "status",
        "alert_data",
        "investigation_created",
        "context_retrieved",
        "analysis_start",
        "analysis_complete",
    ]
    for required in required_types:
        if required not in non_token_types:
            raise AssertionError(f"Missing WebSocket event '{required}'. Events: {non_token_types}")

    if token_count == 0:
        raise AssertionError("No streamed token messages received from LLM pipeline")

    if final_payload is None:
        raise AssertionError("Missing analysis_complete payload")

    if decision_event is None:
        raise AssertionError("Missing final decision event (approval_required or auto_resolved)")

    return {
        "events": non_token_types,
        "token_count": token_count,
        "investigation_id": investigation_id,
        "analysis": final_payload,
        "decision_event": decision_event,
    }


def approve_and_verify(client: TestClient, investigation_id: int) -> None:
    action = client.post(
        f"/api/approvals/{investigation_id}/approve",
        json={"analyst_id": "smoke-test@company.com", "notes": "Approved by smoke test"},
        headers=analyst_headers(),
    )
    action.raise_for_status()
    action_data = action.json()
    if action_data.get("status") != "approved":
        raise AssertionError(f"Approve response had unexpected status: {action_data}")

    inv = client.get(f"/api/investigations/{investigation_id}", headers=service_headers())
    inv.raise_for_status()
    alert_id = int(inv.json()["alert_id"])

    alert = client.get(f"/api/alerts/{alert_id}", headers=service_headers())
    alert.raise_for_status()
    if alert.json().get("status") != "closed":
        raise AssertionError("Alert status did not transition to closed after approval")


def smoke(max_messages: int) -> None:
    with TestClient(app) as client:
        health = client.get("/health")
        health.raise_for_status()
        health_data = health.json()
        if "services" not in health_data:
            raise AssertionError(f"Unexpected health payload: {health_data}")
        print("PASS health", health_data)

        alert_id = ensure_alert(client)
        print(f"PASS alert selected id={alert_id}")

        ws_result = run_websocket_flow(client, alert_id=alert_id, max_messages=max_messages)
        print("PASS websocket events", ws_result["events"])
        print("PASS websocket token_count", ws_result["token_count"])
        print(
            "PASS analysis summary",
            {
                "threat_type": ws_result["analysis"].get("threat_type"),
                "severity_score": ws_result["analysis"].get("severity_score"),
                "recommendation": ws_result["analysis"].get("recommendation"),
            },
        )

        if ws_result["decision_event"] == "approval_required" and ws_result["investigation_id"]:
            approve_and_verify(client, investigation_id=int(ws_result["investigation_id"]))
            print("PASS approval workflow closeout")
        else:
            print("PASS auto-resolve branch", ws_result["decision_event"])

        print("SMOKE TEST PASSED")


def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end ThreatSync smoke test")
    parser.add_argument(
        "--max-messages",
        type=int,
        default=6000,
        help="Maximum websocket messages to process before failing",
    )
    args = parser.parse_args()

    smoke(max_messages=args.max_messages)


if __name__ == "__main__":
    main()
