#!/usr/bin/env python3
"""
Reputation Tracker

Production-ready ReputationTracker for LinkShield's reputation monitoring
subsystem.

Goals:
- Ingest Mention objects (from mention_detector.Mention)
- Persist minimal mention metadata to a chosen backend (in-memory or Redis)
- Compute time-windowed metrics per brand: mention counts, sentiment averages,
  trend scores, rate-of-change, and simple alerting triggers
- Provide async-friendly API suitable for worker/consumer usage

Design notes:
- The tracker expects Mention to contain an optional `metadata['sentiment']`
  float in the range [-1.0, 1.0] (positive -> negative). If not present, the
  tracker will store the mention but exclude it from sentiment aggregates.
- Persistence is abstracted behind a Persistence interface. Redis persistence
  (using aioredis) is provided and optional. When Redis is not available the
  tracker falls back to a safe in-memory store (useful for tests and dev).
- Time windows are handled using Redis sorted-sets (score = unix timestamp)
  or simple lists in memory. This design allows sliding-window queries.

Public API (high level):
- async add_mentions(mentions: Iterable[Mention]) -> None
- async get_brand_metrics(brand: str, window_seconds: int = 86400) -> Dict
- async get_trending_brands(limit: int = 10, window_seconds: int = 3600) -> List
- async get_alerts(config: Dict[str, Any]) -> List[Dict]

Integration points:
- BrandMonitor should call add_mentions when new mentions arrive.
- SentimentAnalyzer should run before (or concurrently) and inject
  metadata['sentiment'] into Mention.metadata. If not available, tracker will
  skip sentiment for that mention.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from ..logging_utils import get_logger

logger = get_logger("ReputationTracker")
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import aioredis
except Exception:  # pragma: no cover - optional dependency
    aioredis = None

logger = logging.getLogger(__name__)


@dataclass
class BrandMetrics:
    brand: str
    window_seconds: int
    mention_count: int
    unique_mentions: int
    sentiment_count: int
    avg_sentiment: Optional[float]
    positive_ratio: Optional[float]
    negative_ratio: Optional[float]
    trend_score: Optional[float]  # simple rate-of-change vs previous window
    last_mention_at: Optional[datetime]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "brand": self.brand,
            "window_seconds": self.window_seconds,
            "mention_count": self.mention_count,
            "unique_mentions": self.unique_mentions,
            "sentiment_count": self.sentiment_count,
            "avg_sentiment": self.avg_sentiment,
            "positive_ratio": self.positive_ratio,
            "negative_ratio": self.negative_ratio,
            "trend_score": self.trend_score,
            "last_mention_at": self.last_mention_at.isoformat() if self.last_mention_at else None,
        }


class Persistence:
    """Abstract persistence interface. Implementations must be async-friendly.

    Methods:
    - async add(brand: str, ts: float, payload: dict)
    - async range(brand: str, ts_from: float, ts_to: float) -> List[dict]
    - async purge_older_than(brand: str, ts_threshold: float)
    - async close()
    """

    async def add(self, brand: str, ts: float, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    async def range(self, brand: str, ts_from: float, ts_to: float) -> List[Dict[str, Any]]:
        raise NotImplementedError

    async def purge_older_than(self, brand: str, ts_threshold: float) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class InMemoryPersistence(Persistence):
    """Simple in-memory persistence for dev and tests.

    Data structure:
      _store: Dict[brand, List[ (ts_float, payload_dict) ] ]

    Note: not suitable for multi-process deployment. Use RedisPersistence
    for production multi-worker setups.
    """

    def __init__(self) -> None:
        self._store: Dict[str, List[Tuple[float, Dict[str, Any]]]] = {}
        self._lock = asyncio.Lock()

    async def add(self, brand: str, ts: float, payload: Dict[str, Any]) -> None:
        async with self._lock:
            self._store.setdefault(brand, []).append((ts, payload))

    async def range(self, brand: str, ts_from: float, ts_to: float) -> List[Dict[str, Any]]:
        async with self._lock:
            entries = self._store.get(brand, [])
            return [p for (ts, p) in entries if ts_from <= ts <= ts_to]

    async def purge_older_than(self, brand: str, ts_threshold: float) -> None:
        async with self._lock:
            entries = self._store.get(brand, [])
            self._store[brand] = [(ts, p) for (ts, p) in entries if ts >= ts_threshold]


class RedisPersistence(Persistence):
    """Redis-backed persistence using sorted sets and JSON serialized payloads.

    Sorted set key per brand: "reputation:{brand}:mentions" with score = timestamp
    Stored value: JSON dump of payload which must include a unique id if required.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0", namespace: str = "reputation"):
        if aioredis is None:
            raise RuntimeError("aioredis is required for RedisPersistence but is not installed.")
        self.redis_url = redis_url
        self.namespace = namespace
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            self._redis = await aioredis.from_url(self.redis_url, decode_responses=True)
        return self._redis

    def _key(self, brand: str) -> str:
        return f"{self.namespace}:{brand}:mentions"

    async def add(self, brand: str, ts: float, payload: Dict[str, Any]) -> None:
        r = await self._get_redis()
        key = self._key(brand)
        await r.zadd(key, {json.dumps(payload): ts})

    async def range(self, brand: str, ts_from: float, ts_to: float) -> List[Dict[str, Any]]:
        r = await self._get_redis()
        key = self._key(brand)
        # zrangebyscore returns list of members
        members = await r.zrangebyscore(key, ts_from, ts_to)
        return [json.loads(m) for m in members]

    async def purge_older_than(self, brand: str, ts_threshold: float) -> None:
        r = await self._get_redis()
        key = self._key(brand)
        await r.zremrangebyscore(key, 0, ts_threshold)

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.close()
            self._redis = None


class ReputationTracker:
    """Main reputation tracker.

    Parameters:
    - persistence: optional Persistence instance. If None, uses InMemoryPersistence.
    - retention_seconds: how long to keep mentions (default 30 days)
    """

    def __init__(self, persistence: Optional[Persistence] = None, retention_seconds: int = 60 * 60 * 24 * 30):
        self.persistence = persistence or InMemoryPersistence()
        self.retention_seconds = retention_seconds

    async def add_mentions(self, mentions: Iterable[Any]) -> None:
        """Ingest Mention objects (dataclass-like). Each mention will be stored
        with minimal payload to keep Redis usage compact.

        Expected Mention fields used here:
          - matched_term (brand)
          - timestamp (datetime)
          - mention_type (str)
          - confidence (float)
          - metadata (dict) -- may include 'sentiment' float in [-1,1]
        """
        tasks = []
        for m in mentions:
            try:
                brand = getattr(m, "matched_term")
                ts_dt = getattr(m, "timestamp")
                if isinstance(ts_dt, datetime):
                    ts = ts_dt.replace(tzinfo=timezone.utc).timestamp()
                else:
                    ts = float(ts_dt)
                payload = {
                    "type": getattr(m, "mention_type", None),
                    "confidence": float(getattr(m, "confidence", 0.0) or 0.0),
                    "text_snippet": getattr(m, "sentiment_context", getattr(m, "text", ""))[:1024],
                    "metadata": getattr(m, "metadata", {}) or {},
                    "added_at": datetime.now(timezone.utc).isoformat(),
                }
                # Normalize sentiment if present
                sent = payload["metadata"].get("sentiment") or payload["metadata"].get("sentiment_score")
                if sent is not None:
                    try:
                        payload["sentiment"] = float(sent)
                    except Exception:
                        payload["sentiment"] = None
                # Persist
                tasks.append(self.persistence.add(brand, ts, payload))
            except Exception as e:
                logger.exception("Failed to add mention: %s", e)
        if tasks:
            await asyncio.gather(*tasks)
        # Purge old data for involved brands
        now_ts = datetime.now(timezone.utc).timestamp()
        purge_before = now_ts - self.retention_seconds
        brands = set(getattr(m, "matched_term") for m in mentions if getattr(m, "matched_term", None))
        purge_tasks = [self.persistence.purge_older_than(brand, purge_before) for brand in brands]
        if purge_tasks:
            await asyncio.gather(*purge_tasks)

    async def get_brand_metrics(self, brand: str, window_seconds: int = 60 * 60 * 24) -> BrandMetrics:
        """Compute metrics for a brand over the last `window_seconds`.

        Strategy:
          - current window: now - window_seconds .. now
          - previous window: now - 2*window_seconds .. now - window_seconds
          - mention_count, unique_mentions (by text_snippet hash), sentiment aggregates
          - trend_score = (current_count - prev_count) / max(prev_count, 1)

        Returns BrandMetrics dataclass.
        """
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()
        window_from = now_ts - window_seconds
        prev_from = now_ts - 2 * window_seconds
        prev_to = window_from

        current = await self.persistence.range(brand, window_from, now_ts)
        previous = await self.persistence.range(brand, prev_from, prev_to)

        mention_count = len(current)
        unique = {p.get("text_snippet") for p in current}
        unique_mentions = len(unique)

        # sentiment
        sentiments = [p.get("sentiment") for p in current if p.get("sentiment") is not None]
        sentiment_count = len(sentiments)
        avg_sentiment = float(sum(sentiments) / sentiment_count) if sentiment_count else None
        positive_ratio = None
        negative_ratio = None
        if sentiment_count:
            pos = sum(1 for s in sentiments if s > 0.05)
            neg = sum(1 for s in sentiments if s < -0.05)
            positive_ratio = pos / sentiment_count
            negative_ratio = neg / sentiment_count

        prev_count = len(previous)
        trend_score = None
        if prev_count > 0:
            trend_score = (mention_count - prev_count) / float(prev_count)
        else:
            trend_score = float(mention_count) if mention_count else 0.0

        last_mention_at = None
        if current:
            try:
                latest_ts = max(float(p.get("added_at_ts", 0)) if p.get("added_at_ts") else 0 for p in current)
                if latest_ts:
                    last_mention_at = datetime.fromtimestamp(latest_ts, tz=timezone.utc)
            except Exception:
                # fallback: parse added_at isoformat
                try:
                    last_iso = max(p.get("added_at") for p in current if p.get("added_at"))
                    last_mention_at = datetime.fromisoformat(last_iso)
                except Exception:
                    last_mention_at = None

        return BrandMetrics(
            brand=brand,
            window_seconds=window_seconds,
            mention_count=mention_count,
            unique_mentions=unique_mentions,
            sentiment_count=sentiment_count,
            avg_sentiment=avg_sentiment,
            positive_ratio=positive_ratio,
            negative_ratio=negative_ratio,
            trend_score=trend_score,
            last_mention_at=last_mention_at,
        )

    async def get_trending_brands(self, limit: int = 10, window_seconds: int = 60 * 60) -> List[Dict[str, Any]]:
        """Return top brands by absolute increase in mentions over previous window.

        Note: For InMemoryPersistence we iterate known keys. For RedisPersistence
        you may want to maintain a brand registry key for efficiency.
        """
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()
        window_from = now_ts - window_seconds
        prev_from = now_ts - 2 * window_seconds
        prev_to = window_from

        # gather brands
        brands = []
        if isinstance(self.persistence, InMemoryPersistence):
            brands = list(self.persistence._store.keys())
        else:
            # best-effort: try to use a registry key if RedisPersistence
            try:
                if isinstance(self.persistence, RedisPersistence):
                    # naive scan by pattern - may be expensive in prod
                    r = await self.persistence._get_redis()
                    pattern = f"{self.persistence.namespace}:*:mentions"
                    keys = await r.keys(pattern)
                    # keys like namespace:brand:mentions
                    brands = [k.split(":", 2)[1] for k in keys]
            except Exception:
                brands = []

        scores = []
        tasks = [self.persistence.range(brand, window_from, now_ts) for brand in brands]
        prev_tasks = [self.persistence.range(brand, prev_from, prev_to) for brand in brands]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        prev_results = await asyncio.gather(*prev_tasks, return_exceptions=True)

        for brand, curr, prev in zip(brands, results, prev_results):
            if isinstance(curr, Exception) or isinstance(prev, Exception):
                continue
            curr_count = len(curr)
            prev_count = len(prev)
            change = curr_count - prev_count
            # score: absolute change scaled by prev_count (avoid div0)
            score = (change / prev_count) if prev_count else float(curr_count)
            scores.append((brand, score, curr_count, prev_count))

        scores.sort(key=lambda x: x[1], reverse=True)
        out = []
        for brand, score, curr_count, prev_count in scores[:limit]:
            out.append({
                "brand": brand,
                "score": score,
                "current_count": curr_count,
                "previous_count": prev_count,
            })
        return out

    async def get_alerts(self, config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Simple alerting engine.

        Config example:
        {
          "brands": {"AcmeCorp": {"threshold_mentions": 50, "window_seconds": 3600}},
          "global": {"threshold_mentions": 200, "window_seconds": 3600}
        }

        Returns list of alert dicts for any triggered alarms.
        """
        alerts = []
        cfg = config or {}
        # collect brands to check
        brands = []
        if isinstance(self.persistence, InMemoryPersistence):
            brands = list(self.persistence._store.keys())
        else:
            try:
                if isinstance(self.persistence, RedisPersistence):
                    r = await self.persistence._get_redis()
                    keys = await r.keys(f"{self.persistence.namespace}:*:mentions")
                    brands = [k.split(":", 2)[1] for k in keys]
            except Exception:
                brands = []

        # global defaults
        global_cfg = cfg.get("global", {})
        for brand in brands:
            brand_cfg = cfg.get("brands", {}).get(brand, {})
            window = brand_cfg.get("window_seconds", brand_cfg.get("window", global_cfg.get("window_seconds", 3600)))
            threshold = brand_cfg.get("threshold_mentions", global_cfg.get("threshold_mentions", 100))
            metrics = await self.get_brand_metrics(brand, window_seconds=window)
            if metrics.mention_count >= threshold:
                alerts.append({
                    "brand": brand,
                    "window_seconds": window,
                    "mention_count": metrics.mention_count,
                    "threshold": threshold,
                    "reason": "mention_count_exceeded",
                })
        return alerts

    async def close(self) -> None:
        await self.persistence.close()


if __name__ == "__main__":
    # basic smoke test
    from datetime import datetime

    async def smoke_test():
        tracker = ReputationTracker()

        # create fake Mention-like objects
        class _M:
            def __init__(self, brand, ts, mention_type="keyword", conf=0.9, sentiment=None, text="x"):
                self.matched_term = brand
                self.timestamp = ts
                self.mention_type = mention_type
                self.confidence = conf
                self.sentiment_context = text
                self.metadata = {"sentiment": sentiment} if sentiment is not None else {}

        now = datetime.now(timezone.utc)
        m1 = _M("AcmeCorp", now - timedelta(minutes=30), sentiment=0.6, text="Love Acme!")
        m2 = _M("AcmeCorp", now - timedelta(minutes=20), sentiment=-0.3, text="Hate Acme")
        m3 = _M("OtherBrand", now - timedelta(minutes=10), sentiment=0.1, text="Other mention")

        await tracker.add_mentions([m1, m2, m3])
        metrics = await tracker.get_brand_metrics("AcmeCorp", window_seconds=3600)
        print(metrics.as_dict())
        trending = await tracker.get_trending_brands()
        print(trending)
        await tracker.close()

    asyncio.run(smoke_test())
