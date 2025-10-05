#!/usr/bin/env python3
"""
Mention Detector

Production-ready MentionDetector and Mention dataclass for LinkShield's
reputation monitoring subsystem.

Responsibilities:
- Configure brands (aliases, handles, keywords, domains, fuzzy matching options)
- Detect mentions in a piece of content (text) for a given platform
- Produce structured Mention objects consumed by BrandMonitor & SentimentAnalyzer

Design principles:
- Async-friendly API (detect_mentions is async)
- Lightweight (no external NLP dependencies) with optional fuzzy matching
- Configurable per-brand patterns and thresholds
- Provide contextual snippet for downstream sentiment analysis

Note: This file integrates with BrandMonitor which expects Mention to be a
`dataclass` with fields used in monitoring and alert logic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Pattern, Any, Tuple
from difflib import SequenceMatcher

# Simple URL regex for domain extraction (not perfect but practical)
_URL_RE = re.compile(
    r"(?:(?:https?):\/\/)?"  # scheme
    r"(?:www\.)?"
    r"(?P<domain>[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(?:[:/\s]|$)",
    flags=re.IGNORECASE,
)


@dataclass
class Mention:
    matched_term: str
    text: str
    start: int
    end: int
    mention_type: str  # 'handle', 'hashtag', 'keyword', 'domain', 'fuzzy'
    confidence: float
    platform: str
    timestamp: datetime
    sentiment_context: str
    metadata: Dict[str, Any] = None


class MentionDetector:
    """Detects brand mentions in arbitrary content.

    Expected brand_config structure (example):
    {
        "AcmeCorp": {
            "aliases": ["acme", "acmecorp"],
            "handles": ["@acmecorp", "@acme"],
            "hashtags": ["#acme", "#acmecorp"],
            "domains": ["acme.com"],
            "fuzzy": True,
            "fuzzy_threshold": 0.85
        }
    }

    The detector compiles regex patterns for fast matching and optionally
    performs fuzzy matching using difflib.SequenceMatcher (pure Python).
    """

    def __init__(
        self,
        brand_config: Optional[Dict[str, Dict[str, Any]]] = None,
        fuzzy_default: bool = True,
        fuzzy_threshold_default: float = 0.85,
        context_window: int = 300,
    ) -> None:
        self.context_window = context_window
        self.fuzzy_default = fuzzy_default
        self.fuzzy_threshold_default = fuzzy_threshold_default
        self._brand_config: Dict[str, Dict[str, Any]] = {}
        self._compiled: Dict[str, Dict[str, List[Pattern]]] = {}
        if brand_config:
            self.configure_brands(brand_config)

    def configure_brands(self, brand_config: Dict[str, Dict[str, Any]]) -> None:
        """Accepts brand configuration and pre-compiles detection patterns.

        This method is idempotent and can be called multiple times to update
        the monitored brands.
        """
        self._brand_config = brand_config.copy()
        self._compiled = {}

        for brand, cfg in self._brand_config.items():
            aliases = cfg.get("aliases", []) or []
            handles = cfg.get("handles", []) or []
            hashtags = cfg.get("hashtags", []) or []
            keywords = cfg.get("keywords", []) or []
            domains = cfg.get("domains", []) or []

            patterns = {
                "handles": [],
                "hashtags": [],
                "keywords": [],
                "domains": [],
            }

            # Precompile handle patterns (@handle or handle without @)
            for h in handles:
                raw = re.escape(h.lstrip("@"))
                patterns["handles"].append(re.compile(rf"@?{raw}\b", flags=re.IGNORECASE))

            # Hashtags (#tag)
            for ht in hashtags:
                raw = re.escape(ht.lstrip("#"))
                patterns["hashtags"].append(re.compile(rf"#?{raw}\b", flags=re.IGNORECASE))

            # Keywords \bword\b
            for kw in set(keywords + aliases):
                raw = re.escape(kw)
                patterns["keywords"].append(re.compile(rf"\b{raw}\b", flags=re.IGNORECASE))

            # Domain simple match
            for d in domains:
                raw = re.escape(d.lower())
                patterns["domains"].append(re.compile(rf"{raw}", flags=re.IGNORECASE))

            self._compiled[brand] = patterns

    async def detect_mentions(
        self, content: str, platform: str, metadata: Optional[Dict[str, Any]] = None
    ) -> List[Mention]:
        """Detect mentions of configured brands in content.

        Returns a list of Mention dataclasses.
        """
        if not content or not self._brand_config:
            return []

        content_lower = content.lower()
        mentions: List[Mention] = []
        now = datetime.now(timezone.utc)

        # Pre-extract domains from content to speed up domain matching
        domains_found = self._extract_domains(content)

        for brand, patterns in self._compiled.items():
            cfg = self._brand_config.get(brand, {})
            fuzzy_enabled = cfg.get("fuzzy", self.fuzzy_default)
            fuzzy_threshold = cfg.get("fuzzy_threshold", self.fuzzy_threshold_default)

            # Exact regex matches: handles, hashtags, keywords
            for ptype in ("handles", "hashtags", "keywords"):
                for pattern in patterns.get(ptype, []):
                    for m in pattern.finditer(content):
                        start, end = m.start(), m.end()
                        snippet = self._context_snippet(content, start, end)
                        mention = Mention(
                            matched_term=brand,
                            text=snippet,
                            start=start,
                            end=end,
                            mention_type=ptype[:-1] if ptype.endswith('s') else ptype,
                            confidence=0.95 if ptype == "keywords" else 0.98,
                            platform=platform,
                            timestamp=now,
                            sentiment_context=snippet,
                            metadata=metadata or {},
                        )
                        mentions.append(mention)

            # Domain matches
            for pattern in patterns.get("domains", []):
                for d in domains_found:
                    if pattern.search(d):
                        # Find approximate position in the content for context
                        idx = content_lower.find(d.lower())
                        if idx >= 0:
                            start = idx
                            end = idx + len(d)
                        else:
                            start, end = 0, 0
                        snippet = self._context_snippet(content, start, end)
                        mention = Mention(
                            matched_term=brand,
                            text=snippet,
                            start=start,
                            end=end,
                            mention_type="domain",
                            confidence=0.90,
                            platform=platform,
                            timestamp=now,
                            sentiment_context=snippet,
                            metadata={**(metadata or {}), "domain": d},
                        )
                        mentions.append(mention)

            # Fuzzy matching on tokens / aliases when enabled
            if fuzzy_enabled:
                aliases = cfg.get("aliases", []) or []
                # tokenise content (simple whitespace tokens)
                tokens = self._tokenize(content)
                for alias in aliases:
                    for token, tok_start, tok_end in tokens:
                        ratio = self._fuzzy_ratio(alias.lower(), token.lower())
                        if ratio >= fuzzy_threshold:
                            snippet = self._context_snippet(content, tok_start, tok_end)
                            confidence = 0.5 + (ratio * 0.45)  # scale to [0.5,~0.95]
                            mention = Mention(
                                matched_term=brand,
                                text=snippet,
                                start=tok_start,
                                end=tok_end,
                                mention_type="fuzzy",
                                confidence=min(confidence, 0.95),
                                platform=platform,
                                timestamp=now,
                                sentiment_context=snippet,
                                metadata={"matched_alias": alias, **(metadata or {})},
                            )
                            mentions.append(mention)

        # De-duplicate mentions by (matched_term, start, end, mention_type)
        unique = {}
        for m in mentions:
            key = (m.matched_term, m.start, m.end, m.mention_type)
            # Prefer higher confidence if duplicate
            if key in unique:
                if m.confidence > unique[key].confidence:
                    unique[key] = m
            else:
                unique[key] = m

        results = list(unique.values())
        # Sort by start index for consistent ordering
        results.sort(key=lambda x: x.start)
        return results

    @staticmethod
    def _context_snippet(content: str, start: int, end: int, window: Optional[int] = None) -> str:
        w = window or 300
        s = max(0, start - w)
        e = min(len(content), end + w)
        return content[s:e].strip()

    @staticmethod
    def _extract_domains(content: str) -> List[str]:
        found = []
        for m in _URL_RE.finditer(content):
            dom = m.group("domain")
            if dom:
                found.append(dom)
        return found

    @staticmethod
    def _tokenize(content: str) -> List[Tuple[str, int, int]]:
        # Very simple tokenizer returning (token, start, end)
        tokens: List[Tuple[str, int, int]] = []
        for match in re.finditer(r"\S+", content):
            tokens.append((match.group(0), match.start(), match.end()))
        return tokens

    @staticmethod
    def _fuzzy_ratio(a: str, b: str) -> float:
        # difflib.SequenceMatcher gives ratio in [0,1]
        if not a or not b:
            return 0.0
        return SequenceMatcher(None, a, b).ratio()


# Backwards compatibility alias
Detector = MentionDetector


if __name__ == "__main__":
    # Quick manual smoke test
    md = MentionDetector(
        {
            "AcmeCorp": {
                "aliases": ["acme", "acmecorp"],
                "handles": ["@AcmeCorp"],
                "hashtags": ["#Acme"],
                "domains": ["acme.com"],
                "fuzzy": True,
                "fuzzy_threshold": 0.8,
            }
        }
    )
    import asyncio

    async def test():
        content = "Check out AcmeCorp's new product! Visit https://acme.com for more. @AcmeCorp #Acme"
        mentions = await md.detect_mentions(content, platform="twitter")
        for m in mentions:
            print(asdict(m))

    asyncio.run(test())
