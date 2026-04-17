import json
from typing import Optional

import redis.asyncio as aioredis

from config import settings


class CacheService:
    def __init__(self) -> None:
        self._client: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        self._client = aioredis.from_url(
            settings.REDIS_URL, decode_responses=True, socket_connect_timeout=5
        )
        # Verify connection
        await self._client.ping()

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> aioredis.Redis:
        if not self._client:
            raise RuntimeError("Redis not connected — call connect() first.")
        return self._client

    # ── Alert queue ───────────────────────────────────────────────

    async def push_alert(self, alert_data: dict) -> None:
        try:
            await self.client.lpush("recent_alerts", json.dumps(alert_data, default=str))
            await self.client.ltrim("recent_alerts", 0, 99)  # keep last 100
        except Exception:
            pass  # non-fatal; primary store is PostgreSQL

    async def get_recent_alerts(self, limit: int = 20) -> list[dict]:
        try:
            raw = await self.client.lrange("recent_alerts", 0, limit - 1)
            return [json.loads(r) for r in raw]
        except Exception:
            return []

    # ── Investigation results ─────────────────────────────────────

    async def cache_investigation(
        self, investigation_id: int, data: dict, ttl: int = 3600
    ) -> None:
        try:
            await self.client.setex(
                f"investigation:{investigation_id}",
                ttl,
                json.dumps(data, default=str),
            )
        except Exception:
            pass

    async def get_cached_investigation(self, investigation_id: int) -> Optional[dict]:
        try:
            raw = await self.client.get(f"investigation:{investigation_id}")
            return json.loads(raw) if raw else None
        except Exception:
            return None

    # ── Approval counters ─────────────────────────────────────────

    async def increment_pending_approvals(self) -> None:
        try:
            await self.client.incr("pending_approvals_count")
        except Exception:
            pass

    async def decrement_pending_approvals(self) -> None:
        try:
            count = await self.client.get("pending_approvals_count")
            if count and int(count) > 0:
                await self.client.decr("pending_approvals_count")
        except Exception:
            pass

    async def get_pending_approvals_count(self) -> int:
        try:
            val = await self.client.get("pending_approvals_count")
            return int(val) if val else 0
        except Exception:
            return 0

    # ── Health ────────────────────────────────────────────────────

    async def health_check(self) -> bool:
        try:
            return bool(await self.client.ping())
        except Exception:
            return False


cache_service = CacheService()
