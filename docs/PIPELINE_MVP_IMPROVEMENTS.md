# Pipeline Accuracy Improvements (MVP)

**Date:** 2026-08-02  
**Goal:** Evidence-based High Risk only — fewer false positives, preserve phishing recall, keep the MVP simple (no ML, no paid APIs).

---

## 1. Rules added or modified

| # | Change | Where |
|---|---|---|
| 1 | **Invoice / billing → weak (weight 10)** | `scoring.py` — `Fake Invoice / BEC Indicators` |
| 2 | **Removed “overdue payment” from strong financial set** | `FINANCIAL_SCAM_PATTERNS` (wire/crypto/gift-card only remain strong) |
| 3 | **High gate = ≥2 strong families only** | Removed alone-path `strong_weight≥40` and `strong≥25 + any weak family` |
| 4 | **Promote Medium→High when ≥2 strong families and score ≥55** | Evidence can outrank a raw score just under 70 |
| 5 | **Display-name brand = whole-word match** | `display_name_brand_conflict()` — no `Pineapple`→`apple` |
| 6 | **Trimmed `HIGH_RISK_TLDS`** | Dropped noisy `.live`, `.support`, `.zip`, `.mov`, etc. |
| 7 | **Core abuse TLDs (`.tk/.ml/.ga/.cf/.gq`) stay strong; other risky TLDs weak** | Sender + header scoring |
| 8 | **Link “suspicious domain”** | Lookalike/punycode **strong 25**; TLD-only **weak 10** |
| 9 | **Auth “Verification mismatch” → weak 8** | Live vs attributed AR noise ≠ forgery |
| 10 | **Domain age → all weak; NRD weights lowered** | Small bump, never High alone |
| 11 | **HTML soft detectors reduced** | Script / event-handler / image-only weights cut |
| 12 | **Removed `sendgrid-php` from suspicious mailers** | Legitimate ESP tooling |

---

## 2. Why each improves accuracy

1–2. Legitimate AR/billing mail no longer stacks two **strong** content hits into High.  
3–4. High Risk means **multiple independent strong families**, matching the checklist; still catches real phishing that scores 55–69 with clear dual evidence.  
5. Stops brand-substring false positives on ordinary company names.  
6–8. New gTLDs and TLD-only links stop burning strong budget; free-country abuse TLDs and lookalikes still count.  
9. Live DNS/IP reconstruction disagreements no longer act like hard auth fails.  
10. Incomplete WHOIS / young domains stay corroborating only.  
11–12. Marketing HTML and SendGrid PHP no longer look like malware tooling.

---

## 3. Trade-offs

| Trade-off | Impact |
|---|---|
| Single strong family (e.g. attachment-only, or wire language alone) stays **Medium** | Analysts must review Medium; pure keyword BEC without TLD/auth/attachment may under-call |
| Noisy gTLDs (`.xyz` From without lookalike) are weak | Slightly easier for `.xyz` phish without other signals — still High when Reply-To diversion / credential / auth fail pair up |
| Medium→High promote at score ≥55 | Real multi-family phishing at 65 becomes High; unlikely to FP because ≥2 strong families are required |
| NRD no longer strong | New phishing domains need a second family (auth fail, lure, bad link) — intentional |

---

## 4. False positives before vs after

Labeled corpus (`tests/validation`): **20 benign / 7 malicious**.

| Metric | Prior accuracy report (13+5) | After Reply-To work (20+7) | After this MVP pass |
|---|---|---|---|
| False positives | 0 / 13 | 0 / 20 | **0 / 20** |
| False negatives | 0 / 5 | 0 / 7 | **0 / 7** |
| Precision / Recall | 1.00 / 1.00 | 1.00 / 1.00 | **1.00 / 1.00** |

**Qualitative FP reduction (not in the synthetic corpus but fixed by these rules):**

| Scenario | Before | After |
|---|---|---|
| Partner invoice + wire wording | Often **High** (invoice+financial strong ≥40) | **Medium** (invoice weak; one strong family) |
| “Pineapple Corp” display name | Brand impersonation **High** | Clean |
| `startup.live` / `.support` sender | Strong high-risk TLD | Not listed / weak |
| Link to `partner.xyz` only | Strong suspicious link | Weak TLD-only |
| Attributed AR vs live “verification mismatch” | Strong auth inconsistency | Weak note |
| SendGrid PHP `X-Mailer` | Suspicious mailer Medium | Ignored |

**Detection preserved:** PayPal/Microsoft spoofs, BEC on `.tk`, malware double-ext, credential harvest, brand→Gmail / brand→`.xyz` Reply-To diversion remain **High/Critical**.

---

## 5. Re-run

```bash
py -m tests.validation.evaluate
py -m pytest tests/unit/test_accuracy_regression.py tests/unit/test_scoring.py tests/unit/test_header_analysis.py tests/unit/test_utils.py -q
```
