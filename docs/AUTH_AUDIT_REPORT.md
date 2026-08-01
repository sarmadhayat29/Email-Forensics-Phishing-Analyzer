# Authentication Verification Engine — Audit & Fix Report

**Date:** 2026-08-01  
**Scope:** SPF / DKIM / DMARC pipeline (`auth_checks.py`, `live_auth.py`, scoring gate)

---

## 1. Root cause

Legitimate messages carried valid **Authentication-Results** (`spf=pass`, `dkim=pass`, `dmarc=pass`) from the receiving MTA, but **live re-verification overwrote those verdicts**.

Typical false cascade:

1. Reconstruct sending IP from the newest public `Received` hop (often wrong for multi-hop / forwarding).
2. Live SPF against that IP → **fail**.
3. Live DKIM finds no signature bytes (stripped / `.msg` / re-serialize) → **none**.
4. Live DMARC uses those speculative results → **fail**.
5. Scoring treats all three as hard/soft failures → **High** (e.g. score 71).

The engine treated “header ≠ live” as “header is forged.” That is incorrect when the AR **authserv-id** aligns with a `Received` `by` host (RFC 8601 attributed result). The border MTA already evaluated SPF against the real connecting IP; reconstructing that IP from header text is unreliable.

---

## 2. Pipeline (after fix)

```
Email
  → parse_message (Authentication-Results, Received, raw_bytes)
  → analyse_authentication (header baseline)
  → live_reverify
        → SPF / DKIM / DMARC live checks (logging each step)
        → merge per mechanism:
              attributed AR + definitive header  → header authoritative
              unattributed / missing AR          → live definitive wins
              DKIM crypto fail on present sig    → live fail always
              temperror / unavailable            → keep header
        → "Verification mismatch" notes (never "Forged" for disagreement alone)
  → score_message
        → auth weights + corroboration gate
        → auth-only strong evidence → Medium max (needs another family for High)
  → Finding / report
```

---

## 3. Bugs found and fixed

| Bug | Fix |
|---|---|
| Live definitive results always overwrote attributed AR PASS | Attributed AR retained for scoring; live recorded as corroboration |
| Disagreement labeled “Forged or stale Authentication-Results” | Relabeled **Verification mismatch** |
| Speculative SPF fail manufactured DMARC fail while overwriting header PASS | DMARC live input uses post-merge SPF/DKIM so retained PASS still aligns |
| SPF identity preferred Return-Path over AR `smtp.mailfrom` | Prefer AR `smtp.mailfrom`, then Return-Path, then From |
| Sending IP only from Received (often wrong hop) | Prefer IP from AR commentary (`designates X as permitted sender`) |
| SPF alignment used exact domain equality | Relaxed organisational-domain alignment |
| `dmarc=temperror/permerror` parsed as `not_present` | Regex extended |
| Ambiguous `p=` / `action=` scraping | Prefer DMARC policy regex |
| Auth hard-fail triple alone → High | Corroboration gate: authentication family alone demotes to Medium |

---

## 4. Files modified

- `src/auth_checks.py` — attribution, merge policy, mismatch wording, logging, identity/IP selection  
- `src/scoring.py` — auth-only High demotion  
- `tests/unit/test_auth_checks.py` — attributed vs unattributed scenarios  
- `tests/unit/test_scoring.py` — auth-alone Medium; auth+impersonation High  

---

## 5. Before vs after (behaviour)

| Scenario | Before | After |
|---|---|---|
| Gmail/GIKI/etc. with attributed AR PASS, live SPF disagrees | SPF FAIL / DKIM NONE / DMARC FAIL → High | Retain PASS; note verification mismatch → Low/Medium |
| Injected unattributed `spf=pass`, live fail | Overwrite to fail (correct) | Still overwrite to fail + mismatch |
| Present DKIM signature, live crypto fail | fail | fail (even if AR attributed) |
| DNS timeout | temperror kept header (OK) | unchanged |
| SPF+DKIM+DMARC fail only | High | **Medium** until another strong family corroborates |

---

## 6. Remaining limitations

- Live SPF evaluator is custom (not pyspf); macros beyond `%{d}`/`%{i}` → temperror.  
- `.msg` inputs still lack byte-exact raw bodies → live DKIM unavailable.  
- ARC / `Received-SPF` not consumed.  
- Attribution uses hostname alignment heuristics; unusual authserv-ids may be treated as unattributed.  
- Cross-checks vs Google Admin Toolbox / MXToolbox require real samples + network (not run in CI).

---

## 7. Recommendations

1. Prefer storing original `.eml` bytes end-to-end for DKIM.  
2. Optionally integrate a maintained SPF library for full macro coverage.  
3. Parse and prefer the newest attributed AR block when multiple headers exist.  
4. Add golden-file fixtures captured from Gmail/Microsoft/GitHub for live regression (offline fakes of their AR + Received shapes).

---

## 8. Tests

```bash
py -3 -m unittest tests.unit.test_auth_checks tests.unit.test_live_auth tests.unit.test_scoring -v
```

All passing after this change.
