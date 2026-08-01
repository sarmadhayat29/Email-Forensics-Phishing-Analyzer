# Accuracy Improvement Report — Email Threat Detection

**Date:** 2026-08-01  
**Scope:** Full pipeline audit of the rule-based scoring engine (`src/scoring.py` and feature extractors).  
**Goal:** Reduce false High/Critical verdicts on legitimate mail without losing real-threat recall.

---

## 1. Root Causes of False Positives

The detector is **100% rule-based** (no ML/LLM). False High Risk came from architecture, not a single bad threshold:

| Root cause | Effect |
|---|---|
| **Weak indicators summed to High** | Urgency wording, “security alert”, invoice language, soft auth (`none`), and missing headers each carried 15–30 points. Several weak signals easily crossed the High cut-off (70) with **no spoofing, malware, or credential-theft evidence**. |
| **Transactional language treated as phishing** | Patterns matched everyday mail: `payment confirmation` (Amazon), `bank deposit` (Chase), `receipt for your payment` (PayPal), bare `reset password` (Google/GitHub). |
| **No trusted-sender context** | Authenticated mail from Google, Microsoft, Amazon, PayPal, Stripe, GitHub was scored the same as unknown senders for content keywords. |
| **Same-site “open redirects”** | Newsletter tracking URLs (`?redirect=https://same-domain/...`) scored like malicious open redirects. |
| **No corroboration gate for High** | High was purely `display_score >= 70`. A pile of weak signals was indistinguishable from multi-family phishing evidence. |
| **Missing-header Medium weights** | Incomplete header sets (or sparse ParsedMessage objects) added 15+15 points, pushing borderline cases into High. |

Baseline audit on 12 legitimate + 3 phishing synthetic cases (**before** fixes): **FP = 2/12**, **FN = 0/3**.

---

## 2. Architectural Improvements

1. **Strong vs weak signal tiers** — Every `PhishingSignal` carries `strength` (`strong`|`weak`), `family`, `original_weight`, and `contribution_pct`.
2. **High/Critical corroboration gate** — Provisional High/Critical is kept only if:
   - ≥2 independent **strong** families, or
   - strong weight ≥ 40, or
   - strong weight ≥ 25 plus corroboration from another family  
   Otherwise demoted to **Medium** with an explicit reason.
3. **Trusted authenticated sender dampening** — When From’s registrable domain is in `TRUSTED_TRANSACTIONAL_DOMAINS` and SPF/DKIM pass (no hard fails), soft content indicators (urgency, invoice/reset/credential keywords, shorteners, redirects) are **suppressed to weight 0** but still listed for analysts.
4. **Narrowed content patterns** — Removed high-FP phrases; urgency/suspicious-keyword weights reduced; missing-header findings softened.
5. **Cross-domain redirect check** — Open-redirect scoring only when the redirect target host differs from the link host.
6. **Explainability** — Verdicts expose `rationale`, `classification_reason`, strong/weak counts, and per-signal contribution %. Surfaced in HTML reports and the investigation UI.

---

## 3. Before vs After (Validation Corpus)

Labeled corpus: **13 benign** + **5 malicious** cases covering GitHub, Google, Microsoft, Amazon, PayPal, bank alerts, newsletters, Stripe invoices, DocuSign, BEC, brand spoofing, and malware attachments.

| Metric | Before (baseline audit) | After |
|---|---|---|
| False positives (benign → High+) | 2 / 12 (~16.7%) | **0 / 13 (0%)** |
| False negatives (malicious → Low/Med) | 0 / 3 | **0 / 5** |
| Precision (High+ = positive) | ~0.60 on small set | **1.00** |
| Recall | 1.00 | **1.00** |
| Accuracy | — | **1.00** |
| F1 | — | **1.00** |

### Confusion matrix (after)

```
                 Pred Malicious   Pred Benign
Actual Malicious       5               0
Actual Benign          0              13
```

Legitimate categories that previously inflated scores (Google security alerts, Amazon payment language, PayPal receipts, internal “urgent” mail) now score **Low** or at most **Medium**. Real phishing (PayPal lookalike + IP link + auth fail), BEC (`.tk` + wire/invoice), credential harvest, and double-extension malware remain **High/Critical**.

---

## 4. How to Re-run Evaluation

```bash
py -3 -m tests.validation.evaluate
py -3 -m unittest tests.unit.test_accuracy_regression tests.unit.test_scoring -v
```

---

## 5. Files Touched

| Area | Files |
|---|---|
| Scoring / gates | `src/scoring.py` |
| Trusted domains | `src/utils.py` |
| Models / explainability | `src/models.py` |
| Reports / UI | `src/report.py`, `src/report_html.py`, `frontend/.../PhishingIndicatorCards.jsx`, `OverallVerdictBanner.jsx` |
| Validation | `tests/validation/corpus.py`, `tests/validation/evaluate.py` |
| Regression tests | `tests/unit/test_accuracy_regression.py` |

---

## 6. Design Invariants Going Forward

- **High Risk requires strong evidence** — never urgency, keywords, HTML alone, or soft auth alone.
- **Authenticated brand mail** may use password-reset / security / invoice language without penalty.
- **Attachments, lookalikes, auth hard-fails, credential harvest, IP links** remain strong and still drive High when corroborated.
- Every verdict must explain **which features contributed, how much, and why the bucket was chosen**.
