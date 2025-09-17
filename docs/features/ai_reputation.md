--------------------------------------------------------
DECISIONS FROM LAST OPEN QUESTIONS
--------------------------------------------------------
1. Probability score → **public** (builds trust), rounded to integer 0-100, key name `ai_confidence`.  
2. Community vote → **store IP-hash + daily salt** (prevents duplicate votes, still GDPR-light).  
3. Social-handle check → **same input box**, regex auto-routes:  
   - `https?://.*@(tiktok|twitter|instagram|youtube)…` → new pipeline  
   - everything else → classic URL pipeline  
   (Zero UI change, zero new endpoint for MVP.)

--------------------------------------------------------
GITHUB-READY TICKETS (4-week sprint)
--------------------------------------------------------
Milestone: “LinkShield AI-reputation v1”

Ticket 1  [FE+BE]  Expose AI confidence in Site-DNA card  
- Backend: modify `url_classifier.py` → return `{"label": "phish", "confidence": 97}`  
- Cache key adds `:v2` suffix to invalidate old entries.  
- Frontend: if confidence ≥ 90 show green lock icon; 50-89 orange; < 50 red.  
- Tests: unit + cypress.

Ticket 2  [BE]  Registrar-age-cert features into RF model  
- Add 3 numeric features to pandas dataframe.  
- Re-train on last 90 days, target F1 ≥ 98 % (current 96.3 %).  
- Store new model artefact `rf_v3.2.joblib` in `/models`, docker image picks it up.

Ticket 3  [BE]  Community flag endpoint  
- `POST /api/v1/flag` body `{"url_hash": "sha256", "verdict": "safe|unsafe"}`  
- IP-hash stored in redis `flag:<daily_salt>:<ip_hash>` → 24 h TTL.  
- Kafka topic `community-flags` produced.  
- Return 204, no leak of existing count.

Ticket 4  [BE]  Surface community meter  
- New column `community_score` in `url_cache` table (0-100).  
- Nightly job aggregates flags → updates score.  
- Card UI shows thin progress bar “Community agrees: 93 % phishing” if ≥ 10 votes.

Ticket 5  [BE]  Brand-Monitor cron + typo-squat detector  
- Daily 02:00 UTC: pull previous-day certstream dump → isolate domains registered < 3 days.  
- MinHash against top 1 k Alexa + 200 hand-curated brands → similarity ≥ 0.85 → insert `typosquat_candidates`.  
- If candidate matches any user watch-list → send email via SendGrid template.

Ticket 6  [BE]  Social-handle pipeline skeleton  
- New file `social_scanner.py` → accepts handle + platform.  
- Uses existing TikTok-Api, tweepy, instaloader keys (add to `.env.example`).  
- Store raw JSON in `social_raw` table (no PII).  
- Return 202 + `scan_id`; poll `GET /scan/status/{id}` → 200 when done.

Ticket 7  [BE]  Phishing-keyword detector on social posts  
- Re-use `keyword_detector.py` → run on bio + last 10 captions.  
- Output `keyword_risk_score` 0-100.  
- Merge into final social response.

Ticket 8  [FE]  Social-handle auto-route in input box  
- Regex list in `utils.js` → if match, call `/scan/social` instead of `/scan/url`.  
- Same card UI, just extra row “Crypto-scam keywords 12 %”.

Ticket 9  [BE+FE]  Embed model version & last-retrain in every response  
- Add headers `X-Model-Version` and `X-Model-Date`.  
- Badge iframe shows tiny footer “Model v3.2 updated 2 days ago”.

Ticket 10  [Ops]  Weekly retrain CI  
- GitHub action every Sunday 00:00 → pulls last 7 days flagged URLs → retrain RF → push artefact to S3 → open PR to bump model pointer.  
- Auto-roll-back if F1 drops > 1 % on hold-out set.

--------------------------------------------------------
API CONTRACT CHANGES (minimal)
--------------------------------------------------------
Classic scan endpoint  
`GET /api/v1/scan?url=example.com`  
Response adds:
```json
{
  "ai_confidence": 97,
  "community_score": 93,
  "model": {"version": "3.2", "retrain_date": "2025-09-15"}
}
```

New social scan endpoint  
`POST /api/v1/scan/social`  
Body:
```json
{
  "platform": "tiktok",
  "handle": "elonmusk_real"
}
```
Response (when finished):
```json
{
  "handle": "elonmusk_real",
  "platform": "tiktok",
  "ai_confidence": 88,
  "keyword_risk_score": 12,
  "impersonation_score": 75,
  "model": {"version": "3.2", "retrain_date": "2025-09-15"}
}
```

--------------------------------------------------------
METRICS & SUCCESS CRITERIA
--------------------------------------------------------
- Median scan latency ≤ 1.2 s (today 0.8 s) → acceptable 50 % increase.  
- Community vote spam ≤ 2 % (measure duplicate IP-hash).  
- Brand-Monitor MRR: 50 paying users (€5/month) within 3 months.  
- Social-handle usage: 1 000 scans/day within 6 weeks (tracked via Plausible custom event).

--------------------------------------------------------
WHAT’S NEXT AFTER THIS MILESTONE
--------------------------------------------------------
- Discord / Slack bot (ticket 11)  
- Relay disposable redirect (ticket 12)  
- STIX-2 threat feed (ticket 13)  

But we **cut scope now** and ship v1 first.

--------------------------------------------------------
YOUR MOVE
--------------------------------------------------------
1. Any ticket to **drop / merge / re-order**?  
2. Do we **open a public roadmap page** (GitHub project board) so contributors can pick up tickets?  
3. **Date lock**: sprint starts Mon 23 Sep, ends Fri 18 Oct – OK?

Say “go” and I’ll open the GitHub issues and the milestone.
