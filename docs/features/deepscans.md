--------------------------------------------------------
WORKING TITLE — “Deep-Link Audit” (DLA)
--------------------------------------------------------
One input → two new cards:

A. **Website Deep-Link Audit**  
Paste *any* website URL → we spider **up to N pages** (home, about, blog, product pages, social bio links, footer links) → extract **every external URL** → batch-scan them → surface **aggregate risk**.

B. **Social Feed Link Audit**  
Paste *any* social handle → we fetch **last K posts** (or video descriptions) → extract **every outbound link** (including Link-in-bio, shortened URLs, Telegram/Discord invite, crypto wallet drainer, etc.) → batch-scan → surface **aggregate risk**.

--------------------------------------------------------
USER-STORY SNAPSHOT
--------------------------------------------------------
• **Brand manager**: “Our blog just got hacked and now injects ‘update Flash’ links — catch it before Twitter mobs us.”  
• **Influencer**: “I want to audit my last 100 TikTok captions to prove I’m not accidentally shilling scam crypto.”  
• **Casual user**: “This shopping site looks legit, but what **other** sites do they link to?”

--------------------------------------------------------
MINIMAL UI / UX (no new pages)
--------------------------------------------------------
Current result card gets an **expandable section**:

┌─ Deep-Link Audit  ▸ ───────────────────────────────┐  
│  124 unique outbound links scanned · 3 flagged     │  
│  ⚠️  1 malware (wallet drainer)                    │  
│  ⚠️  2 phishing (fake Nike shop)                   │  
│  🔍  View full list (CSV export)  ──premium─────── │  
└────────────────────────────────────────────────────┘

Click → slide-down table (paginated 20 rows)  
Columns: linked URL, anchor text, page where found, LinkShield verdict, first seen.

--------------------------------------------------------
TECH & SCOPE BOUNDS (keep it cheap)
--------------------------------------------------------
Spider depth  
- Website: max 25 pages, max 100 external links (respect robots nofollow).  
- Social: last 50 posts/media, max 100 links (uses platform API, no scraping if token missing).

Short-url expansion  
- Expand bit.ly, t.co, tinyurl.com, discord.gg, telegram.me, etc. **before** scan (already have code for 3 services).

Deduplication  
- Normalise to second-level domain + path → sha256 → Redis set → scan only once per 24 h.

Rate-limit  
- Deep scans count as **5 normal scans** against quota (configurable).

Async by default  
- Return `scan_id` immediately; poll `/scan/deep/{id}/status` → websocket optional later.

--------------------------------------------------------
API CONTRACT (additive)
--------------------------------------------------------
POST /api/v1/scan/deep  
Body:
```json
{
  "target": "https://fashionstore.com",
  "type": "website",        // or "social"
  "platform": null,         // required if type=social
  "max_pages": 25,
  "max_links": 100
}
```
202 Accepted → header `Location: /scan/deep/abc123`

GET /scan/deep/abc123  
200 when finished:
```json
{
  "target": "https://fashionstore.com",
  "type": "website",
  "summary": {
    "total_links": 124,
    "unique_links": 87,
    "flagged": 3,
    "malware": 1,
    "phishing": 2,
    "unknown": 0
  },
  "flagged_links": [
    {
      "url": "https://wallet-update.vercel.app/app/",
      "found_on": "/blog/fall-collection",
      "anchor": "Download our NFT wallet",
      "verdict": "malware",
      "confidence": 96
    }
  ],
  "csv_export_url": "/api/v1/export/deep/abc123?token=JWT"
}
```

--------------------------------------------------------
RE-USING EXISTING AI STACK
--------------------------------------------------------
• Same Random-Forest/BERT classifier → just called in **batch** (Celery chord).  
• Community-flag votes **already** improve verdicts for obscure links.  
• Keyword detector runs on **anchor text** + **surrounding paragraph** → extra feature for classifier.  
• Isolation-Forest: if a domain suddenly appears in **> x** different deep-scans within 24 h → mark as **emerging threat** and prioritise in public feed.

--------------------------------------------------------
PRIVACY & ETHICS GUARDRAILS
--------------------------------------------------------
- We **never** store the **full HTML**, only extracted **external URLs** + **sha256 of page snippet** (for duplicate check).  
- Respect canonical `robots.txt` → drop pages disallowed.  
- Social token scopes: **read-only**, no user data persisted beyond handle & post-id hash.  
- **Opt-in** for social scan: user must explicitly choose “social” type (no silent scanning).

--------------------------------------------------------
MONETISATION HOOKS
--------------------------------------------------------
Free tier  
- 5 deep-scans / month (website or social)  
- CSV export disabled, table paginated at 10 rows.

Premium ($5/mo or 50 000 sats/mo)  
- 200 deep-scans / month  
- CSV + JSON export  
- “Monitor this bundle” → auto re-scan weekly, email if **new** flagged link appears.

Team / Agency ($20/mo)  
- 1 000 deep-scans + bulk API + webhook.

--------------------------------------------------------
EFFORT ESTIMATE (S-M-L)
--------------------------------------------------------
Backend: M (new spider service, Celery chord, dedup logic, export token).  
Frontend: S (reuse same card, just new section).  
DevOps: S (no new infra, just extra Celery queue `deep-scan`).  
Total calendar time: ~3 weeks parallel with current sprint.

--------------------------------------------------------
OPEN QUESTIONS FOR YOU
--------------------------------------------------------
1. Max pages / links limits OK? (25 / 100)  
2. Do we **auto-trigger** deep-scan when user clicks “Expand” (cost surprise) or **ask confirmation** “This will consume 5 scans”?  
3. Social scan: start with **TikTok + Twitter only**? (Instagram needs scraping fallback → more fragile).  
4. Do we show **safe links count** too, or only **flagged** to keep UI compact?

Give me a thumbs-up or tweaks and I’ll open the GitHub issue + add it to the milestone.
