
---
## 1. The Idea in One Sentence  
LinkShield is the **“safety scanner for everything you meet online”** – one box, one click, and you instantly know if a **website**, **social account**, or **the links they share** is safe, shady, or dangerous.
---

## 2. Who Is It For?  
- **Casual users** – check a link before you click.  
- **Shoppers** – check a store before you pay.  
- **Influencers** – prove your profile and last posts are clean.  
- **Brand managers** – watch your own site & socials 24/7 and get an alert if anything turns bad.

---

## 3. What Can You Do? (Features in Plain Words)  

| Feature | Free | Logged-in (subscribers) |
|---|---|---|
| **Quick Scan** – paste ANY link → green / red card in 2 s | ✅ unlimited | ✅ |
| **Site-DNA card** – tiny “why” section: age, certs, reviews | ✅ first 5 / day | ✅ unlimited |
| **Deep-Link Audit** – see **all** outbound links of that site and their safety | ✅ 3 scans / month | ✅ 200 / month |
| **Social Safety** – paste `@handle` or TikTok/Instagram/Youtube/LinkedIn URL → get account age, fake-follower check, scam-keywords in bio & last posts | ✅ 5 scans / month | ✅ 200 / month |
| **Community Meter** – small bar “93 % of users flagged this as scam” | ✅ | ✅ |
| **Watch-list (monitor)** – we re-check **your** site or handle every day and email you if it turns bad | ❌ | ✅ |
| **Export CSV / JSON** – download full lists of flagged links | ❌ | ✅ |
| **Bulk API** – send 100 links at once | ❌ | ✅ |

*Everything uses the **same input box** on the home page.  
Subscribers also get a **simple dashboard** to pick “Scan once” or “Monitor”.*

---

## 4. How It Works (Behind the Curtains)  
1. You paste something.  
2. We **guess** what you gave us:  
   - looks like `https://…` → **website scan**  
   - looks like `@username` or `tiktok.com/@xyz` → **social scan**  
3. We fetch public data → run **AI + 40 threat lists + community votes** → build a **card**.  
4. If you are **monitoring**, we store a **hash** of the address (no personal data) and repeat the scan every night.

---

## 5. Detailed Development Plan  
*FastAPI + PostgreSQL + Redis + Celery – same stack you already have.*

### PHASE 0 – Prepare (week 1)  
- [ ] Create GitHub milestone `LS-v1-deep-rep`  
- [ ] Add env variables:  
  `MAX_FREE_DEEP=3`, `MAX_FREE_SOCIAL=5`, `MONITOR_ENABLED=false` (upgraded users)  

### PHASE 1 – Quick Wins (weeks 1-2)  
**Back-end**  
- [ ] Return **confidence %** in `/scan` → `ai_confidence` field  
- [ ] Add **registrar-age-cert** features to Random-Forest → new model `rf_v3.2.joblib`  
- [ ] Store **community votes** (IP-hash + daily salt) → Kafka topic + Postgres table `community_vote`  

**Front-end**  
- [ ] Collapsible **Site-DNA card** (age, certs, rank) – shows after scan  
- [ ] Tiny **community meter** bar under card  

### PHASE 2 – Deep-Link Audit (weeks 2-3)  
**Back-end**  
- [ ] New endpoint `POST /api/v1/scan/deep` → returns `scan_id` (202)  
- [ ] Spider:  
  - max 25 pages, max 100 external links, obey `robots.txt`  
  - deduplicate by second-level domain + path sha256  
- [ ] Celery chord: expand short URLs → batch-call existing classifier → save results  
- [ ] New table `deep_scan` + `deep_link` (foreign key)  
- [ ] Route `/export/deep/{id}?token=JWT` → CSV (premium only)  

**Front-end**  
- [ ] Add **“Deep-Link Audit ▸”** row in card (free users see first 10 rows, paginated)  

### PHASE 3 – Social Safety (weeks 3-4)  
**Back-end**  
- [ ] Regex router in `/scan` → if pattern = social → redirect to `POST /api/v1/scan/social`  
- [ ] Platform modules: `tiktok.py`, `twitter.py`, `instagram.py` (read-only tokens)  
- [ ] Fetch: account meta + last 50 posts/media → extract **bio link + caption links**  
- [ ] Run **keyword detector** on bio + captions → `keyword_risk_score`  
- [ ] Run **follower spike detector** (Isolation-Forest on timeseries) → `impersonation_score`  
- [ ] Re-use Deep-Link chord for **all extracted links**  

**Front-end**  
- [ ] Show **social card**: verification badge, age, scores, flagged links table  

### PHASE 4 – Monitoring & Dashboard (week 4)  
**Back-end**  
- [ ] New table `watchlist` (user_id, target_hash, type, created_at)  
- [ ] Nightly cron → re-scans entries → if **new** flagged links or verdict change → send email  
- [ ] Simple **Stripe checkout** → on success set `MONITOR_ENABLED=true`  

**Front-end dashboard** (subscribers only)  
- [ ] Tabs: “Quick Scan”, “My Watch-list”, “Export History”  
- [ ] Buttons: “Add to watch-list” appears after any scan  

### PHASE 5 – Harden & Measure (week 5, buffer)  
- [ ] Add **rate-limit**: deep scans count as 5 normal scans  
- [ ] Write **tests** (unit ≥ 80 %, Cypress smoke)  
- [ ] **Metrics** dashboard: median latency ≤ 1.2 s, community spam ≤ 2 %  
- [ ] Update public **docs** (Swagger + entry-level FAQ)  

---

## 6. What We DO NOT Build (Keep It Light)  
- No browsing-history storage  
- No private-profile scraping  
- No credit-score-style consumer reports  
- No closed-source browser extension (stay web-first)

---

## 7. Success Numbers We Want  
- 1 000 deep scans/day within 6 weeks  
- 50 paying monitor users (€5/month) within 3 months  
- F1 score ≥ 98 % on URL classifier after adding registrar features  

---

## 8. Next Click for You  
👍 **Approve** → I open all GitHub issues and start code branches.  
🔄 **Tweak numbers** → tell me and I update the plan.
