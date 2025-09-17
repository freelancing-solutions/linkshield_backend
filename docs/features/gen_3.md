# TARGET-MARKET × FEATURE MATRIX (real desks, real budgets)

|  #  | Target Market (real job titles) | Core Pain they wake up with | Feature that kills the pain | Will they pay? | What they feed back to us |
|-----|---------------------------------|-----------------------------|-----------------------------|----------------|---------------------------|
| 1   | **Everyday shopper** (teen to grand-mom) | “Is this shoe site a scam?” | **Safety Lens** (2-second green/red) | NO – free only | Community vote (right/wrong) |
| 2   | **Micro-influencer** 5k-100k followers | “Brand wants screenshot proof I’m clean” | **Reputation badge** (0-100) + **CSV export** | YES – €5/mo | Social post data (public) |
| 3   | **E-commerce manager** Shopify / Woo | “My supplier links to fake Nike” | **Deep-Link Audit** (outbound links) | YES – €20/mo | Affiliate URL lists |
| 4   | **Brand Protection Manager** (Nike, L’Oréal) | “800 copy-cats appeared last night” | **Radar Lens** (look-alikes) + **Monitor** | YES – €500/mo | Cert-stream hits |
| 5   | **SOC Analyst** (MSSP, bank) | “Need IOCs in STIX in 60 s” | **Threat-Intel Lens** (STIX bundle) | YES – €500-5k/mo | FP flag → trains model |
| 6   | **Law-Enforcement / CERT** | “Need evidence pack for takedown” | **Evidence Lens** (PNG + PCAP + signed JSON) | YES – €2k per case | Seized server lists |
| 7   | **C-Suite / Board member** | “What’s our external risk score today?” | **Executive Lens** (peer-benchmark dashboard) | YES – €5k/mo | Internal phish samples |
| 8   | **Media / News desk** | “Is this source legit & original?” | **Content Originality** + **Reputation** | YES – €100-1k/mo | Fact-check labels |
| 9   | **Ad Agency / Brand-safety team** | “Will this creative get disapproved?” | **Brand-Risk Lens** (IAB topics + sentiment) | YES – €200-2k/mo | Ad creative corpus |

---

## FEATURE → MARKET RE-CHECK

| Feature | Free taste | Micro-inf €5 | Brand Mgr €20 | SOC/CERT €500-5k | News/Ad €100-2k |
|---------|------------|--------------|---------------|------------------|-----------------|
| Safety badge (green/red) | ✅ unlimited | ✅ | ✅ | ✅ (SLA) | ✅ |
| Reputation score 0-100 | ✅ badge only | ✅ full | ✅ | ✅ | ✅ |
| Deep-Link Audit (outbound) | 3 links | 200 | 500 | 50k/mo | 1k |
| Radar look-alikes | count only | 10 | 100 | 10k/mo | 100 |
| Content originality % | number | number | full list | full | full |
| Content summary (topics/sentiment) | 1 line | 1 line | full | full | full |
| Threat-Intel (STIX + IOC) | ❌ | ❌ | ❌ | ✅ | ❌ |
| Evidence pack (PNG+PCAP+signed) | ❌ | ❌ | ❌ | per-case €2k | ❌ |
| Executive dashboard (risk meter) | ❌ | ❌ | ❌ | ✅ | ❌ |
| Brand-risk (IAB + ad-policy) | ❌ | ❌ | ❌ | ✅ | ✅ |
| Monitor + Alerts | ❌ | 5 assets | 20 | unlimited | 50 |

---

## BUILD ORDER (money first, buzz second)
1. **Safety + Reputation** – keeps free tier alive (1 week)  
2. **Deep-Link + Radar** – unlocks Brand Mgr €20 (week 2)  
3. **Threat-Intel + Evidence** – unlocks SOC/CERT €500-5k (week 3)  
4. **Executive dashboard** – unlocks C-suite €5k (week 4)  
5. **Brand-risk + News originality** – unlocks Agency + News €100-2k (week 5)

---

Vote:  
👍  = lock the matrix and open GitHub milestones per tier  
🔄  = tweak numbers / limits
