import json
import os
import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


async def seed_alerts(db: AsyncSession) -> int:
    from db.models import Alert, AlertStatus

    mock_data_dir = os.path.dirname(__file__)
    with open(os.path.join(mock_data_dir, "alerts.json")) as f:
        alerts_data = json.load(f)

    count = 0
    for item in alerts_data:
        alert = Alert(
            alert_uuid=str(uuid.uuid4()),
            alert_type=item["alert_type"],
            user_id=item.get("user_id"),
            source_ip=item.get("source_ip"),
            hostname=item.get("hostname"),
            severity_hint=item.get("severity_hint"),
            raw_data=item["raw_data"],
            status=AlertStatus.NEW,
            occurred_at=datetime.fromisoformat(item["occurred_at"]),
        )
        db.add(alert)
        count += 1

    await db.commit()
    return count


async def seed_initial_data() -> None:
    """Seed the database with mock data only if it is empty."""
    from db.database import AsyncSessionLocal
    from db.models import Alert

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(func.count(Alert.id)))
        existing = result.scalar()

        if existing == 0:
            seeded = await seed_alerts(db)
            print(f"  Seeded {seeded} mock alerts into the database.")
        else:
            print(f"  Database already contains {existing} alert(s) — skipping seed.")
