import asyncio
import json
import os
import re
from typing import Optional

from config import settings


def _is_mock_mode() -> bool:
    key = settings.OPENAI_API_KEY or ""
    return not key or key.startswith("sk-your") or key == "sk-placeholder"


class RAGPipeline:
    """
    Manages three ChromaDB vector collections:
      - threat_intel   : curated threat intelligence entries
      - user_activity  : per-user behavioural history
      - past_alerts    : previously investigated alerts (grows at runtime)
    """

    def __init__(self) -> None:
        self.embeddings = None
        self.threat_intel_store = None
        self.user_activity_store = None
        self.past_alerts_store = None
        self._mock_threat_intel: list[dict] = []
        self._mock_user_activity: list[dict] = []
        self._mock_past_alerts: list[dict] = []
        self._initialized = False

    _ALERT_CATEGORY_HINTS: dict[str, list[str]] = {
        "login_failure": ["brute_force", "rdp_attack"],
        "malware_detection": ["malware_c2"],
        "data_exfiltration": ["insider_threat"],
        "lateral_movement": ["lateral_movement"],
        "anomalous_behavior": ["impossible_travel"],
        "c2_communication": ["apt28_tactics", "malware_c2"],
        "privilege_escalation": ["privilege_escalation"],
    }

    # ── Initialisation ────────────────────────────────────────────

    async def initialize(self) -> None:
        if _is_mock_mode():
            await self._load_mock_collections()
            self._initialized = True
            return  # Skip OpenAI embeddings — no API key available

        from langchain_chroma import Chroma
        from langchain_openai import OpenAIEmbeddings

        self.embeddings = OpenAIEmbeddings(
            model=settings.OPENAI_EMBEDDING_MODEL,
            api_key=settings.OPENAI_API_KEY,
        )

        chroma_kwargs = {
            "embedding_function": self.embeddings,
            "persist_directory": settings.CHROMA_PERSIST_DIR,
        }

        self.threat_intel_store = await asyncio.to_thread(
            lambda: Chroma(collection_name="threat_intel", **chroma_kwargs)
        )
        self.user_activity_store = await asyncio.to_thread(
            lambda: Chroma(collection_name="user_activity", **chroma_kwargs)
        )
        self.past_alerts_store = await asyncio.to_thread(
            lambda: Chroma(collection_name="past_alerts", **chroma_kwargs)
        )

        await self._seed_if_empty()
        self._initialized = True

    async def _load_mock_collections(self) -> None:
        """Load local JSON datasets used by fallback retrieval when no API key is set."""
        mock_dir = os.path.join(os.path.dirname(__file__), "..", "mock_data")

        with open(os.path.join(mock_dir, "threat_intel.json"), encoding="utf-8") as f:
            self._mock_threat_intel = json.load(f)

        with open(os.path.join(mock_dir, "user_activity.json"), encoding="utf-8") as f:
            self._mock_user_activity = json.load(f)

    async def _seed_if_empty(self) -> None:
        count = await asyncio.to_thread(
            lambda: self.threat_intel_store._collection.count()
        )
        if count == 0:
            await self._seed_threat_intel()
            await self._seed_user_activity()

    async def _seed_threat_intel(self) -> None:
        from langchain_core.documents import Document

        mock_dir = os.path.join(os.path.dirname(__file__), "..", "mock_data")
        with open(os.path.join(mock_dir, "threat_intel.json")) as f:
            entries = json.load(f)

        docs = [
            Document(
                page_content=item["description"],
                metadata={
                    "category": item["category"],
                    "iocs": json.dumps(item.get("iocs", [])),
                    "mitre_tactics": json.dumps(item.get("mitre_tactics", [])),
                    "severity": item.get("severity", "medium"),
                    "source": item.get("source", "internal"),
                },
            )
            for item in entries
        ]
        await asyncio.to_thread(lambda: self.threat_intel_store.add_documents(docs))

    async def _seed_user_activity(self) -> None:
        from langchain_core.documents import Document

        mock_dir = os.path.join(os.path.dirname(__file__), "..", "mock_data")
        with open(os.path.join(mock_dir, "user_activity.json")) as f:
            entries = json.load(f)

        docs = [
            Document(
                page_content=(
                    f"User {e['user_id']} performed '{e['action']}' on "
                    f"'{e['resource']}' from {e.get('source_ip', 'unknown')} "
                    f"at {e['timestamp']}. Success: {e.get('success', True)}."
                    + (f" Note: {e['note']}" if e.get("note") else "")
                ),
                metadata={
                    "user_id": e["user_id"],
                    "action": e["action"],
                    "success": str(e.get("success", True)),
                    "timestamp": e["timestamp"],
                },
            )
            for e in entries
        ]
        await asyncio.to_thread(lambda: self.user_activity_store.add_documents(docs))

    # ── Retrieval ─────────────────────────────────────────────────

    async def retrieve_context(
        self,
        alert_type: str,
        user_id: Optional[str],
        raw_data: dict,
    ) -> dict:
        if not self._initialized:
            return {"threat_intel": [], "user_activity": [], "similar_alerts": []}

        if _is_mock_mode():
            return self._retrieve_context_mock(
                alert_type=alert_type,
                user_id=user_id,
                raw_data=raw_data,
            )

        # Build a natural-language query from the alert
        raw_values = " ".join(
            str(v) for v in raw_data.values() if isinstance(v, (str, int, float))
        )
        alert_query = f"{alert_type} {raw_values}".strip()

        # Threat intel retrieval
        threat_docs = await asyncio.to_thread(
            lambda: self.threat_intel_store.similarity_search(
                alert_query, k=settings.RAG_TOP_K
            )
        )
        threat_intel = [
            {"content": d.page_content, "metadata": d.metadata} for d in threat_docs
        ]

        # User activity retrieval (filtered by user_id when available)
        user_activity: list[dict] = []
        if user_id:
            user_query = f"user {user_id} recent activity login access"
            try:
                user_docs = await asyncio.to_thread(
                    lambda: self.user_activity_store.similarity_search(
                        user_query,
                        k=settings.RAG_TOP_K,
                        filter={"user_id": user_id},
                    )
                )
                user_activity = [
                    {"content": d.page_content, "metadata": d.metadata}
                    for d in user_docs
                ]
            except Exception:
                pass

        # Similar past alerts (only if collection is non-empty)
        similar_alerts: list[dict] = []
        past_count = await asyncio.to_thread(
            lambda: self.past_alerts_store._collection.count()
        )
        if past_count > 0:
            past_docs = await asyncio.to_thread(
                lambda: self.past_alerts_store.similarity_search(alert_query, k=3)
            )
            similar_alerts = [
                {"content": d.page_content, "metadata": d.metadata}
                for d in past_docs
            ]

        return {
            "threat_intel": threat_intel,
            "user_activity": user_activity,
            "similar_alerts": similar_alerts,
        }

    def _retrieve_context_mock(
        self,
        alert_type: str,
        user_id: Optional[str],
        raw_data: dict,
    ) -> dict:
        query = f"{alert_type} {self._raw_values_text(raw_data)}".strip()
        tokens = set(self._tokenize(query))
        hint_categories = set(self._ALERT_CATEGORY_HINTS.get(alert_type, []))

        threat_candidates: list[tuple[int, dict]] = []
        for entry in self._mock_threat_intel:
            iocs_text = " ".join(entry.get("iocs", []))
            mitre_text = " ".join(entry.get("mitre_tactics", []))
            haystack = " ".join(
                [
                    str(entry.get("category", "")),
                    str(entry.get("description", "")),
                    str(entry.get("severity", "")),
                    iocs_text,
                    mitre_text,
                ]
            ).lower()
            score = self._token_overlap_score(haystack, tokens)
            if entry.get("category") in hint_categories:
                score += 3
            threat_candidates.append(
                (
                    score,
                    {
                        "content": entry.get("description", ""),
                        "metadata": {
                            "category": entry.get("category", ""),
                            "iocs": json.dumps(entry.get("iocs", [])),
                            "mitre_tactics": json.dumps(entry.get("mitre_tactics", [])),
                            "severity": entry.get("severity", "medium"),
                            "source": entry.get("source", "internal"),
                        },
                    },
                )
            )

        threat_candidates.sort(key=lambda x: x[0], reverse=True)
        top_threat = threat_candidates[: settings.RAG_TOP_K]
        threat_intel = [item for _, item in top_threat]

        user_items = self._mock_user_activity
        if user_id:
            user_items = [u for u in user_items if u.get("user_id") == user_id]
        user_items = sorted(user_items, key=lambda x: str(x.get("timestamp", "")), reverse=True)
        user_activity = [
            {
                "content": (
                    f"User {u.get('user_id')} performed '{u.get('action')}' on "
                    f"'{u.get('resource')}' from {u.get('source_ip', 'unknown')} "
                    f"at {u.get('timestamp')}. Success: {u.get('success', True)}."
                    + (f" Note: {u.get('note')}" if u.get("note") else "")
                ),
                "metadata": {
                    "user_id": u.get("user_id"),
                    "action": u.get("action"),
                    "success": str(u.get("success", True)),
                    "timestamp": u.get("timestamp"),
                },
            }
            for u in user_items[: settings.RAG_TOP_K]
        ]

        similar_candidates: list[tuple[int, dict]] = []
        for doc in self._mock_past_alerts:
            score = self._token_overlap_score(str(doc.get("content", "")), tokens)
            similar_candidates.append((score, doc))
        similar_candidates.sort(key=lambda x: x[0], reverse=True)
        similar_alerts = [item for score, item in similar_candidates if score > 0][:3]

        return {
            "threat_intel": threat_intel,
            "user_activity": user_activity,
            "similar_alerts": similar_alerts,
        }

    @staticmethod
    def _raw_values_text(raw_data: dict) -> str:
        parts: list[str] = []
        for value in raw_data.values():
            if isinstance(value, (str, int, float, bool)):
                parts.append(str(value))
            elif isinstance(value, list):
                parts.extend(str(v) for v in value)
            elif isinstance(value, dict):
                parts.extend(str(v) for v in value.values())
        return " ".join(parts)

    @staticmethod
    def _token_overlap_score(text: str, tokens: set[str]) -> int:
        if not text:
            return 0
        words = set(RAGPipeline._tokenize(text))
        return len(words.intersection(tokens))

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        return re.findall(r"[a-z0-9_]+", text.lower())

    # ── Post-investigation storage ────────────────────────────────

    async def store_investigation(self, alert: dict, investigation: dict) -> None:
        """Add a completed investigation to the past-alerts collection for future RAG."""
        if _is_mock_mode():
            content = (
                f"Alert type: {alert.get('alert_type')}. "
                f"User: {alert.get('user_id', 'unknown')}. "
                f"Summary: {investigation.get('summary', '')}. "
                f"Threat: {investigation.get('threat_type', '')}. "
                f"Severity: {investigation.get('severity_score', '')}. "
                f"Recommendation: {investigation.get('recommendation', '')}."
            )
            self._mock_past_alerts.append(
                {
                    "content": content,
                    "metadata": {
                        "alert_type": alert.get("alert_type", ""),
                        "threat_type": investigation.get("threat_type", ""),
                        "severity_score": str(investigation.get("severity_score", 5)),
                        "recommendation": investigation.get("recommendation", ""),
                    },
                }
            )
            return

        if not self._initialized or self.past_alerts_store is None:
            return

        from langchain_core.documents import Document

        content = (
            f"Alert type: {alert.get('alert_type')}. "
            f"User: {alert.get('user_id', 'unknown')}. "
            f"Summary: {investigation.get('summary', '')}. "
            f"Threat: {investigation.get('threat_type', '')}. "
            f"Severity: {investigation.get('severity_score', '')}. "
            f"Recommendation: {investigation.get('recommendation', '')}."
        )
        doc = Document(
            page_content=content,
            metadata={
                "alert_type": alert.get("alert_type", ""),
                "threat_type": investigation.get("threat_type", ""),
                "severity_score": str(investigation.get("severity_score", 5)),
                "recommendation": investigation.get("recommendation", ""),
            },
        )
        await asyncio.to_thread(lambda: self.past_alerts_store.add_documents([doc]))


rag_pipeline = RAGPipeline()
