# ThreatSync AI Investigator

An AI-powered Security Operations Center (SOC) investigation platform.
Security alerts are ingested, relevant context is retrieved via a RAG pipeline,
and an LLM generates a structured threat investigation that streams in real time
to an analyst dashboard.

```
Alert → RAG (user logs + threat intel) → LLM: "brute force or insider threat?"
     → Structured JSON (severity, steps, IOCs, MITRE tactics)
     → WebSocket stream → Dashboard → Human-in-loop approval
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API / Backend | Python 3.11 · FastAPI · Uvicorn |
| Database | PostgreSQL (async via asyncpg + SQLAlchemy 2) |
| Vector store | ChromaDB (persistent, local) |
| Embeddings | OpenAI `text-embedding-3-small` |
| LLM reasoning | OpenAI GPT-4o-mini via LangChain LCEL |
| Streaming | FastAPI WebSocket + LangChain `astream` |
| Caching | Redis (async) |
| Frontend | Vanilla HTML / CSS / JS (served by FastAPI) |
| Containers | Docker + Docker Compose |

---

## Project Structure

```
ThreatSync AI Investigator/
├── backend/
│   ├── main.py                  # FastAPI app + lifespan hooks
│   ├── config.py                # Pydantic-settings config
│   ├── db/
│   │   ├── database.py          # Async SQLAlchemy engine & session
│   │   └── models.py            # ORM models: Alert, Investigation, Approval
│   ├── schemas/
│   │   ├── alert.py             # AlertCreate / AlertResponse
│   │   └── investigation.py     # InvestigationResponse / ApprovalAction
│   ├── services/
│   │   ├── rag_pipeline.py      # ChromaDB collections + retrieval
│   │   ├── llm_service.py       # LangChain LCEL investigation chain
│   │   └── cache.py             # Redis async helpers
│   ├── api/
│   │   ├── alerts.py            # GET/POST /api/alerts
│   │   ├── investigations.py    # GET /api/investigations
│   │   ├── approvals.py         # GET/POST /api/approvals
│   │   └── websocket.py         # WS /ws/investigations/{alert_id}
│   └── mock_data/
│       ├── alerts.json          # 8 realistic SOC alerts
│       ├── user_activity.json   # Per-user behavioural history
│       ├── threat_intel.json    # 8 threat intel documents
│       └── seed.py              # DB + vector store seeding
├── frontend/
│   ├── index.html               # SOC dashboard
│   ├── styles.css               # Dark theme
│   └── app.js                   # WebSocket client + API calls
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## Quick Start

### Option A — Docker Compose (recommended)

```bash
# 1. Clone / open the project
cd "ThreatSync AI Investigator"

# 2. Create .env from the example
cp .env.example .env
# Edit .env and set OPENAI_API_KEY=sk-...

# 3. Start everything
docker compose up --build

# 4. Open the dashboard
open http://localhost:8000
```

### Option B — Local Python

**Prerequisites:** Python 3.11+, PostgreSQL 14+, Redis 7+

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create and configure .env
cp .env.example .env
# Set DATABASE_URL, REDIS_URL, OPENAI_API_KEY

# 3. Start the app
cd backend
uvicorn main:app --reload --port 8000

# 4. Open the dashboard
open http://localhost:8000
```

---

## API Reference

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/alerts` | List all alerts (`?status=new&alert_type=login_failure`) |
| `POST` | `/api/alerts` | Ingest a new alert |
| `GET`  | `/api/alerts/{id}` | Get a single alert |
| `POST` | `/api/alerts/seed` | Re-seed mock data (dev) |

### Investigations

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/investigations` | List all investigations |
| `GET`  | `/api/investigations/{id}` | Get a specific investigation |
| `GET`  | `/api/investigations/alert/{alert_id}` | Get investigations for an alert |

### Approvals (Human-in-loop)

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/approvals/pending` | List investigations awaiting approval |
| `GET`  | `/api/approvals/{investigation_id}` | Get approval status |
| `POST` | `/api/approvals/{investigation_id}/approve` | Approve |
| `POST` | `/api/approvals/{investigation_id}/reject` | Reject |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/audit` | List audit events (`?action=approval_approved&actor=analyst@company.com`) |

### WebSocket

```
WS /ws/investigations/{alert_id}
```

Real-time investigation stream. Server pushes a sequence of typed JSON messages:

| `type` | Payload | Notes |
|--------|---------|-------|
| `status` | `phase`, `message` | Pipeline phase updates |
| `alert_data` | `data` | Alert details |
| `investigation_created` | `investigation_id` | DB record created |
| `context_retrieved` | `data` | RAG retrieval summary |
| `analysis_start` | — | LLM begins streaming |
| `token` | `content` | Individual LLM token |
| `analysis_complete` | `data`, `investigation_id` | Full structured result |
| `approval_required` | `investigation_id`, `severity_score` | Severity ≥ 7 |
| `auto_resolved` | `recommendation` | Severity < 7 |
| `error` | `message` | Error description |

---

## Investigation Output Schema

```json
{
  "threat_type": "brute_force | insider_threat | malware | data_exfiltration | lateral_movement | c2_communication | privilege_escalation | anomaly | false_positive",
  "severity_score": 8.5,
  "confidence": 0.91,
  "summary": "47 authentication failures in 5 minutes from a Belarusian IP...",
  "key_findings": ["..."],
  "investigation_steps": [
    {"step": 1, "action": "Block source IP 185.220.101.47 at firewall", "rationale": "..."}
  ],
  "iocs": ["185.220.101.47", "libcurl/7.81.0"],
  "mitre_tactics": ["T1110 - Brute Force", "T1110.003 - Password Spraying"],
  "recommendation": "escalate | monitor | ignore",
  "estimated_risk": "critical | high | medium | low"
}
```

---

## Mock Scenarios

Eight pre-loaded alerts cover the most common SOC scenarios:

| Alert | User | Type |
|-------|------|------|
| VPN brute force | john.doe | 47 failures / 5 min from Belarus |
| Trojan dropper | mary.smith | Temp svchost.exe → C2 port 4444 |
| Data exfiltration | bob.johnson | 2 GB upload + resignation context |
| RDP admin spray | admin | 312 attempts / 30 min, Russia |
| Lateral movement | service_account | 28 SMB hops in 15 min |
| Impossible travel | alice.wong | SF → Moscow in 135 min via Tor |
| DNS tunnelling C2 | charlie.brown | APT28, 1847 queries/hr |
| Privilege escalation | dave.miller | Token impersonation → SYSTEM |

---

## Approval Workflow

Investigations with `severity_score >= 7.0` (configurable via `APPROVAL_THRESHOLD`)
are automatically escalated to the approval queue. An analyst must approve or reject
before the alert is marked as `closed`.

Approvals below the threshold are auto-resolved based on the LLM recommendation.

---

## Interactive Docs

- Swagger UI: http://localhost:8000/api/docs
- ReDoc:      http://localhost:8000/api/redoc

---

## End-to-End Smoke Test

Run a one-command regression smoke that starts the API, verifies REST + WebSocket
investigation phases, and validates approval workflow closure when required.

```bash
cd backend
python smoke_e2e.py
```

### CI Automation

The repository includes a GitHub Actions workflow at
`.github/workflows/smoke-e2e.yml` that runs this same smoke flow on push and
pull requests. It provisions PostgreSQL in CI and executes `python smoke_e2e.py`
from the backend folder.

---

## Production Hardening

### 1. Enable API Authentication / RBAC

Set these in `.env`:

```env
API_AUTH_ENABLED=true
API_KEY_SERVICE=<strong-random-key-for-service-clients>
API_KEY_ANALYST=<strong-random-key-for-analysts>
```

- Service endpoints (`/api/alerts`, `/api/investigations`) require `X-API-Key`
- Approvals and audit endpoints require `X-Analyst-Key`
- WebSocket endpoint requires `api_key` query parameter

### 2. Frontend Key Injection (if auth enabled)

In browser dev tools, set keys once:

```js
localStorage.setItem('threatsync.serviceApiKey', '<service-key>')
localStorage.setItem('threatsync.analystApiKey', '<analyst-key>')
location.reload()
```

### 3. Audit Trail

The backend now stores investigation and approval events in `audit_events`.
Query via `/api/audit` for analyst review and compliance traceability.
