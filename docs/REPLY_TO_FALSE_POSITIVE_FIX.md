# Reply-To / Domain Matching — False Positive Reduction

## Problem

The analyzer treated any From ≠ Reply-To (and many Sender / Return-Path differences) as Medium or High risk. That is common and legitimate for universities, banks, help desks, CRMs, and ESP-backed mail.

## Logic changes

### 1. Organization-level domain matching (`same_organization`)

Hosts that share a registrable domain (including multi-label suffixes such as `edu.pk`) are treated as one organisation.

| Example | Result |
| --- | --- |
| `company.com` ↔ `mail.company.com` | Same org |
| `giki.edu.pk` ↔ `portal.giki.edu.pk` | Same org |
| `paypal.com` ↔ `gmail.com` | Not same org |

**FP impact:** Same-org Reply-To / Sender / Return-Path no longer raise risk.

### 2. Trusted ESP / CRM recognition (`is_legitimate_esp`)

Expanded allowlist: SendGrid, Mailgun, Brevo, Mailchimp, UniSend, Amazon SES, SparkPost, Postmark, Zendesk, Freshdesk, HubSpot, Salesforce, Microsoft 365 infra, Google Workspace infra, Zoho Mail infra, etc.

Consumer free-mail hosts (`gmail.com`, `outlook.com`, …) are **not** treated as trusted ESPs for Reply-To diversion checks.

**FP impact:** Third-party sending / bounce / ticketing infrastructure alone does not increase threat score.

### 3. Relationship classifier (`domain_relationship`)

Returns `same_org` | `trusted_esp` | `suspicious` | `unrelated`.

| Pattern | Class | Scoring |
| --- | --- | --- |
| `noreply@company.com` → `support@company.com` | same_org | No Reply-To finding |
| `noreply@acme.com` → `support@acme.zendesk.com` | trusted_esp | No Reply-To finding |
| `paypal.com` → `gmail.com` | suspicious | High / strong |
| `microsoft.com` → `*.xyz` | suspicious | High / strong |
| `company.com` → `partner.org` | unrelated | Medium / weak only |

**Detection preserved:** Brand or corporate From with free-mail / high-risk TLD / lookalike Reply-To remains a strong phishing / BEC signal.

### 4. Header forensics rewrite (`header_analysis.py`)

- `_check_from_vs_reply_to`: silence on same org / ESP; High only for `suspicious`; weak Medium for plain `unrelated`.
- `_check_from_vs_sender` / `_check_from_vs_return_path`: same taxonomy (Low for org/ESP; High only with deception evidence).

### 5. Standalone scoring path (`scoring.py`)

Replaced strong “Mismatched Sender Domains” with:

- **Suspicious Reply / Sender Diversion** (strong) — deception evidence only
- **Different Sender Header Domains** (weak) — organisational difference without corroboration

Medium Reply-To / Return-Path “difference” findings map to weak weights so they cannot alone drive High/Critical.

### 6. Trusted-sender dampening exception

Authenticated brand From (PayPal, Microsoft, …) normally suppresses soft content signals. That dampening is **disabled** when Reply-To / Sender / Return-Path is classified `suspicious` (e.g. PayPal → Gmail), so reply diversion plus lure language still reaches High without opening FPs for normal brand mail.

## What still detects real phishing

- Free-mail or high-risk TLD Reply-To from a non-free-mail From
- Lookalike / typosquat domains
- Display-name brand impersonation
- Credential harvesting, malicious URLs, auth failures, malware attachments (unchanged)

Legitimate infrastructure differences require **additional independent indicators** before Medium/High classification.
