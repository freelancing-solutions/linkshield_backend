"""
broken_link_scanner.py
Production-grade broken-link & threat scanner for linkshield.site
- Verbose mode uses injected security services
- Returns nested link-tree with PR-score & threat labels
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any, Set

import aiohttp
from aiohttp import ClientTimeout, ClientSession
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, robots
from enum import Enum

from pydantic import BaseModel, Field

# ------------------------------------------------------------------
# Domain models (unchanged)
# ------------------------------------------------------------------
class BrokenLinkStatus(str, Enum):
    WORKING = "working"
    BROKEN = "broken"
    TIMEOUT = "timeout"
    REDIRECT = "redirect"
    UNKNOWN = "unknown"
    SLOW = "slow"
    SERVER_ERROR = "server_error"


class ThreatType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    SPAM = "spam"
    BAD_REPUTATION = "bad_reputation"
    DOMAIN_SQUAT = "domain_squat"
    URL_SHORTENER_REDIRECT = "url_shortener_redirect"
    SLOW = "slow"
    BROKEN = "broken"
    BAD_CONTENT = "bad_content"


class BrokenLinkDetail(BaseModel):
    url: str
    status_code: Optional[int] = None
    status: BrokenLinkStatus
    error_message: Optional[str] = None
    response_time: Optional[float] = None
    redirect_url: Optional[str] = None
    depth_level: int

    class Config:
        extra = "forbid"


class LinkNode(BaseModel):
    url: str
    status_code: Optional[int] = None
    status: BrokenLinkStatus
    response_time: Optional[float] = None
    depth_level: int
    threats: List[ThreatType] = Field(default_factory=list)
    pr_score: float = 100.0
    children: List["LinkNode"] = Field(default_factory=list)

    def add_threat(self, t: ThreatType) -> None:
        if t not in self.threats:
            self.threats.append(t)
        self._recalc_pr()

    def _recalc_pr(self) -> None:
        total = sum(THREAT_WEIGHT.get(t, 0) for t in self.threats)
        self.pr_score = max(0.0, 100.0 - (total * 10))

    class Config:
        extra = "forbid"


class BrokenLinkScanResult(BaseModel):
    total_links_found: int = 0
    total_links_checked: int = 0
    broken_links_count: int = 0
    working_links_count: int = 0
    slow_links_count: int = 0
    scan_depth_used: int = 1
    max_links_used: int = 100
    broken_links: List[BrokenLinkDetail] = Field(default_factory=list)
    scan_duration: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.dict()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BrokenLinkScanResult":
        return cls(**data)


class VerboseScanResult(BrokenLinkScanResult):
    verbose: bool = True
    link_tree: Optional[LinkNode] = None
    threat_summary: Dict[ThreatType, int] = Field(default_factory=dict)
    lowest_pr_score: float = 100.0

    def build_summary(self) -> None:
        counter: Dict[ThreatType, int] = {t: 0 for t in ThreatType}
        self.lowest_pr_score = 100.0

        def walk(node: LinkNode):
            for t in node.threats:
                counter[t] += 1
            self.lowest_pr_score = min(self.lowest_pr_score, node.pr_score)
            for child in node.children:
                walk(child)

        if self.link_tree:
            walk(self.link_tree)
        self.threat_summary = counter


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
@dataclass
class ScanConfig:
    max_depth: int = 2
    max_links: int = 100
    request_timeout: int = 10
    root_page_timeout: int = 30
    max_redirects: int = 5
    respect_robots_txt: bool = True
    user_agent: str = "LinkShieldBot/1.0 (+https://linkshield.site/bot)"
    allow_external: bool = True
    delay_between_requests: float = 0.0
    semaphore_limit: int = 30
    slow_threshold: float = 3.0
    verbose: bool = False


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------
logger = logging.getLogger("broken_link_scanner")

THREAT_WEIGHT = {
    ThreatType.MALWARE: 10,
    ThreatType.PHISHING: 10,
    ThreatType.SPAM: 3,
    ThreatType.BAD_REPUTATION: 5,
    ThreatType.DOMAIN_SQUAT: 5,
    ThreatType.URL_SHORTENER_REDIRECT: 3,
    ThreatType.SLOW: 1,
    ThreatType.BROKEN: 3,
    ThreatType.BAD_CONTENT: 3,
}


class RobotsCache:
    _cache: Dict[str, Optional[robots.RobotFileParser]] = {}

    @classmethod
    def allowed(cls, url: str, user_agent: str) -> bool:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in cls._cache:
            try:
                rp = robots.RobotFileParser()
                rp.set_url(urljoin(base, "/robots.txt"))
                rp.read()
                cls._cache[base] = rp
            except Exception:
                cls._cache[base] = None
        rp = cls._cache[base]
        return rp is None or rp.can_fetch(user_agent, url)


# ------------------------------------------------------------------
# Broken Link Scanner – renamed & with security services
# ------------------------------------------------------------------
class BrokenLinkScanner:
    """
    Production scanner that accepts security services for verbose threat analysis.
    """

    def __init__(
        self,
        *,
        domain_squat_analyzer: Optional[Any] = None,
        pattern_analyzer: Optional[Any] = None,
        shortener_analyzer: Optional[Any] = None,
    ) -> None:
        self.session: Optional[ClientSession] = None
        self.domain_squat_analyzer = domain_squat_analyzer
        self.pattern_analyzer = pattern_analyzer
        self.shortener_analyzer = shortener_analyzer

    # ----------------------------------------------------------
    # Public API – unchanged
    # ----------------------------------------------------------
    async def scan(
        self,
        url: str,
        *,
        config: Optional[ScanConfig] = None,
    ) -> BrokenLinkScanResult:
        cfg = config or ScanConfig()
        t0 = time.perf_counter()

        connectors = aiohttp.TCPConnector(limit=cfg.semaphore_limit, ssl=True)
        timeout = ClientTimeout(total=cfg.root_page_timeout)
        async with ClientSession(
            connector=connectors,
            timeout=timeout,
            headers={"User-Agent": cfg.user_agent},
        ) as session:
            self.session = session
            try:
                if cfg.verbose:
                    result = await self._crawl_verbose(url, cfg)
                else:
                    result = await self._crawl(url, cfg)
            finally:
                self.session = None

        result.scan_duration = round(time.perf_counter() - t0, 2)
        return result

    # ----------------------------------------------------------
    # Classic (non-verbose) crawl – identical to previous version
    # ----------------------------------------------------------
    async def _crawl(self, start_url: str, cfg: ScanConfig) -> BrokenLinkScanResult:
        start_url = urljoin(start_url, "/")
        domain = urlparse(start_url).netloc

        to_crawl: List[Tuple[str, int]] = [(start_url, 0)]
        seen: Set[str] = set()
        all_links: List[str] = []

        while to_crawl:
            current_url, depth = to_crawl.pop(0)
            if current_url in seen or depth > cfg.max_depth:
                continue
            seen.add(current_url)

            html = await self._fetch(current_url)
            if html is None:
                continue

            extracted = self._extract_links(html, current_url)
            for link in extracted:
                if link in seen:
                    continue
                if not cfg.allow_external and urlparse(link).netloc != domain:
                    continue
                if cfg.respect_robots_txt and not RobotsCache.allowed(link, cfg.user_agent):
                    continue
                all_links.append(link)
                if depth + 1 <= cfg.max_depth:
                    to_crawl.append((link, depth + 1))

        unique_links = list(dict.fromkeys(all_links))[: cfg.max_links]

        sem = asyncio.Semaphore(cfg.semaphore_limit)
        check_tasks = [self._check_link(url, sem, cfg) for url in unique_links]
        check_results = await asyncio.gather(*check_tasks)

        broken = [
            r for r in check_results
            if r.status in {BrokenLinkStatus.BROKEN, BrokenLinkStatus.TIMEOUT, BrokenLinkStatus.SERVER_ERROR, BrokenLinkStatus.UNKNOWN}
        ]
        slow = [r for r in check_results if r.status == BrokenLinkStatus.SLOW]
        working = [r for r in check_results if r.status == BrokenLinkStatus.WORKING]

        return BrokenLinkScanResult(
            total_links_found=len(all_links),
            total_links_checked=len(check_results),
            broken_links_count=len(broken),
            working_links_count=len(working),
            slow_links_count=len(slow),
            scan_depth_used=cfg.max_depth,
            max_links_used=cfg.max_links,
            broken_links=broken,
        )

    # ----------------------------------------------------------
    # Verbose crawl – builds LinkNode tree using security services
    # ----------------------------------------------------------
    async def _crawl_verbose(self, start_url: str, cfg: ScanConfig) -> VerboseScanResult:
        start_url = urljoin(start_url, "/")
        domain = urlparse(start_url).netloc
        seen: Set[str] = set()
        all_nodes: List[LinkNode] = []

        async def build_node(url: str, depth: int) -> Optional[LinkNode]:
            if url in seen or depth > cfg.max_depth or len(all_nodes) >= cfg.max_links:
                return None
            seen.add(url)

            html = await self._fetch(url)
            node_data = await self._check_link_verbose(url, cfg)
            node = LinkNode(url=url, depth_level=depth, **node_data)

            if html:
                extracted = self._extract_links(html, url)
                child_tasks = []
                for link in extracted:
                    if not cfg.allow_external and urlparse(link).netloc != domain:
                        continue
                    if cfg.respect_robots_txt and not RobotsCache.allowed(link, cfg.user_agent):
                        continue
                    child_tasks.append(build_node(link, depth + 1))
                child_nodes = await asyncio.gather(*child_tasks)
                node.children = [c for c in child_nodes if c]

            all_nodes.append(node)
            return node

        root_node = await build_node(start_url, 0)
        result = VerboseScanResult(
            total_links_found=len(all_nodes),
            total_links_checked=len(all_nodes),
            broken_links_count=sum(
                1 for n in all_nodes
                if ThreatType.BROKEN in n.threats or n.status in {
                    BrokenLinkStatus.BROKEN, BrokenLinkStatus.TIMEOUT,
                    BrokenLinkStatus.SERVER_ERROR, BrokenLinkStatus.UNKNOWN
                }
            ),
            working_links_count=sum(1 for n in all_nodes if n.status == BrokenLinkStatus.WORKING and not n.threats),
            slow_links_count=sum(1 for n in all_nodes if ThreatType.SLOW in n.threats),
            scan_depth_used=cfg.max_depth,
            max_links_used=cfg.max_links,
            link_tree=root_node,
        )
        result.build_summary()
        return result

    # ----------------------------------------------------------
    # Fetch single page
    # ----------------------------------------------------------
    async def _fetch(self, url: str) -> Optional[str]:
        try:
            async with self.session.get(url, allow_redirects=True) as resp:
                if resp.status != 200 or resp.content_type != "text/html":
                    return None
                return await resp.text()
        except Exception as exc:
            logger.debug("Fetch failed for %s: %s", url, exc)
            return None

    # ----------------------------------------------------------
    # Extract links from HTML
    # ----------------------------------------------------------
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, "lxml")
        links: List[str] = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].split("#")[0]
            if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            absolute = urljoin(base_url, href)
            if absolute.startswith(("http://", "https://")):
                links.append(absolute)
        return links

    # ----------------------------------------------------------
    # Threat analyser – uses injected services
    # ----------------------------------------------------------
    async def _analyse_threats(self, url: str, elapsed: float, cfg: ScanConfig, html: Optional[str] = None) -> List[ThreatType]:
        threats: List[ThreatType] = []

        if elapsed > cfg.slow_threshold:
            threats.append(ThreatType.SLOW)

        if self.domain_squat_analyzer:
            squat_result = await self.domain_squat_analyzer.analyze_domain(url, fetch_content=False)
            if squat_result.is_squatting:
                threats.append(ThreatType.DOMAIN_SQUAT)

        if self.shortener_analyzer:
            short_result = await self.shortener_analyzer.analyze_shortener(url)
            if short_result.is_shortener and short_result.risk_assessment in {"suspicious", "malicious"}:
                threats.append(ThreatType.URL_SHORTENER_REDIRECT)

        if self.pattern_analyzer and html:
            pattern_result = self.pattern_analyzer.analyze_content(html, url)
            if pattern_result.overall_risk_score > 0.7:
                threats.append(ThreatType.BAD_CONTENT)
            if any(m.category in {"phishing", "credential_harvesting"} for m in pattern_result.pattern_matches):
                threats.append(ThreatType.PHISHING)
            if any(m.category == "malware" for m in pattern_result.pattern_matches):
                threats.append(ThreatType.MALWARE)

        return threats

    # ----------------------------------------------------------
    # Check link – verbose version returns dict for LinkNode
    # ----------------------------------------------------------
    async def _check_link_verbose(self, url: str, cfg: ScanConfig) -> Dict[str, Any]:
        t0 = time.perf_counter()
        status_code: Optional[int] = None
        error: Optional[str] = None
        redirect: Optional[str] = None
        base_status: BrokenLinkStatus
        html: Optional[str] = None
        try:
            timeout = ClientTimeout(total=cfg.request_timeout)
            async with self.session.head(
                url, allow_redirects=True, timeout=timeout, ssl=True
            ) as resp:
                elapsed = time.perf_counter() - t0
                status_code = resp.status
                if 200 <= resp.status < 400:
                    base_status = BrokenLinkStatus.WORKING
                elif 400 <= resp.status < 500:
                    base_status = BrokenLinkStatus.BROKEN
                else:
                    base_status = BrokenLinkStatus.SERVER_ERROR
                if resp.url.human_repr() != url:
                    redirect = str(resp.url)
        except asyncio.TimeoutError:
            base_status = BrokenLinkStatus.TIMEOUT
            elapsed = time.perf_counter() - t0
            error = "Request timeout"
        except Exception as exc:
            base_status = BrokenLinkStatus.BROKEN
            elapsed = time.perf_counter() - t0
            error = str(exc)

        if base_status == BrokenLinkStatus.WORKING:
            html = await self._fetch(url)

        threats = await self._analyse_threats(url, elapsed, cfg, html)
        if base_status in (BrokenLinkStatus.BROKEN, BrokenLinkStatus.TIMEOUT, BrokenLinkStatus.SERVER_ERROR):
            threats.append(ThreatType.BROKEN)
        threats = list(set(threats))

        node = LinkNode(
            url=url,
            status_code=status_code,
            status=base_status,
            response_time=round(elapsed, 3),
            redirect_url=redirect,
            depth_level=1,
            threats=threats,
        )
        node._recalc_pr()
        return node.dict()

    # ----------------------------------------------------------
    # Check link – classic (non-verbose)
    # ----------------------------------------------------------
    async def _check_link(
        self, url: str, sem: asyncio.Semaphore, cfg: ScanConfig
    ) -> BrokenLinkDetail:
        async with sem:
            t0 = time.perf_counter()
            try:
                timeout = ClientTimeout(total=cfg.request_timeout)
                async with self.session.head(
                    url, allow_redirects=True, timeout=timeout, ssl=True
                ) as resp:
                    elapsed = time.perf_counter() - t0
                    if 200 <= resp.status < 400:
                        status = (
                            BrokenLinkStatus.SLOW
                            if elapsed > cfg.slow_threshold
                            else BrokenLinkStatus.WORKING
                        )
                    elif 400 <= resp.status < 500:
                        status = BrokenLinkStatus.BROKEN
                    else:
                        status = BrokenLinkStatus.SERVER_ERROR

                    return BrokenLinkDetail(
                        url=url,
                        status_code=resp.status,
                        status=status,
                        response_time=round(elapsed, 3),
                        redirect_url=str(resp.url) if resp.url.human_repr() != url else None,
                        depth_level=1,
                    )
            except asyncio.TimeoutError:
                return BrokenLinkDetail(
                    url=url,
                    status=BrokenLinkStatus.TIMEOUT,
                    error_message="Request timeout",
                    depth_level=1,
                )
            except Exception as exc:
                return BrokenLinkDetail(
                    url=url,
                    status=BrokenLinkStatus.UNKNOWN,
                    error_message=str(exc),
                    depth_level=1,
                )


# ------------------------------------------------------------------
# Quick CLI sanity check
# ------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def demo():
        from domain_squatting_analyzer import DomainSquattingAnalyzer
        from suspicious_pattern_analyzer import SuspiciousPatternAnalyzer
        from url_shortener_analyzer import URLShortenerAnalyzer

        scanner = BrokenLinkScanner(
            domain_squat_analyzer=DomainSquattingAnalyzer(),
            pattern_analyzer=SuspiciousPatternAnalyzer(),
            shortener_analyzer=URLShortenerAnalyzer(),
        )
        result = await scanner.scan(
            "https://linkshield.site",
            config=ScanConfig(verbose=True, slow_threshold=1.5)
        )
        print(result.json(indent=2))

    asyncio.run(demo())