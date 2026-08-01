"""Labeled validation corpus for threat-detection accuracy.

Each case is a synthetic but realistic message with an expected risk band.
``benign`` cases must not reach High/Critical. ``malicious`` cases must.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from models import ParsedMessage, AuthVerdict, RoutingVerdict, Attachment


Label = Literal["benign", "malicious"]


@dataclass(frozen=True)
class ValidationCase:
    id: str
    label: Label
    category: str
    parsed: ParsedMessage
    auth: AuthVerdict
    routing: RoutingVerdict = field(default_factory=lambda: RoutingVerdict(hop_count=3))
    #: For benign: highest acceptable risk. For malicious: lowest acceptable.
    expected_ceiling: str = "Medium"
    expected_floor: str = "High"


def _pass() -> AuthVerdict:
    return AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")


def _none() -> AuthVerdict:
    return AuthVerdict(raw="", source="", spf="none", dkim="none", dmarc="none")


def _fail() -> AuthVerdict:
    return AuthVerdict(raw="", source="", spf="fail", dkim="fail", dmarc="fail")


def _msg(**kwargs) -> ParsedMessage:
    defaults = dict(
        message_id="<id@example.com>",
        date="Sat, 01 Aug 2026 12:00:00 +0000",
        to_raw="user@example.com",
    )
    defaults.update(kwargs)
    return ParsedMessage(**defaults)


def build_validation_corpus() -> list[ValidationCase]:
    """Return the full labeled corpus used by the accuracy harness."""
    cases: list[ValidationCase] = []

    # --- Legitimate / benign -------------------------------------------------
    benign_specs = [
        (
            "legit_github_pr",
            "github",
            _msg(
                from_raw="GitHub <noreply@github.com>",
                subject="[org/repo] Pull request merged",
                body_plain="Your pull request #42 was merged. https://github.com/org/repo/pull/42",
            ),
            _pass(),
        ),
        (
            "legit_google_security",
            "google",
            _msg(
                from_raw="Google <no-reply@accounts.google.com>",
                subject="Security alert",
                body_plain=(
                    "New sign-in on Windows. If this was you, no action needed. "
                    "If not, visit https://accounts.google.com/signin"
                ),
            ),
            _pass(),
        ),
        (
            "legit_microsoft_security",
            "microsoft",
            _msg(
                from_raw="Microsoft account team <account-security-noreply@accountprotection.microsoft.com>",
                subject="Unusual sign-in activity",
                body_plain="We detected a sign-in. Review activity: https://account.microsoft.com/security",
            ),
            _pass(),
        ),
        (
            "legit_amazon_order",
            "amazon",
            _msg(
                from_raw="Amazon.com <auto-confirm@amazon.com>",
                subject="Your Amazon.com order has shipped",
                body_plain="Your payment confirmation for order 123-456. Track: https://www.amazon.com/gp/css/order-history",
            ),
            _pass(),
        ),
        (
            "legit_paypal_receipt",
            "paypal",
            _msg(
                from_raw="PayPal <service@paypal.com>",
                subject="You sent a payment to Acme",
                body_plain="You paid Acme $42.00 USD. View activity: https://www.paypal.com/myaccount/activity",
            ),
            _pass(),
        ),
        (
            "legit_bank_alert",
            "bank",
            _msg(
                from_raw="Chase <no.reply@alerts.chase.com>",
                subject="Deposit available",
                body_plain="A deposit of $500.00 is available in your account ending in 1234.",
            ),
            _pass(),
        ),
        (
            "legit_newsletter",
            "newsletter",
            _msg(
                from_raw="Digest <news@newsletter.example.com>",
                subject="This week in tech",
                body_html='<p>Read more <a href="https://example.com/a?utm_source=nl&redirect=https://example.com/story">here</a></p>',
            ),
            _pass(),
        ),
        (
            "legit_stripe_invoice",
            "invoice",
            _msg(
                from_raw="Stripe <support@stripe.com>",
                subject="Invoice #49204 from Acme Inc",
                body_plain="Invoice #49204 for $99.00. Payment due Aug 15. Manage billing at https://dashboard.stripe.com",
            ),
            _pass(),
        ),
        (
            "legit_github_password_reset",
            "password_reset",
            _msg(
                from_raw="GitHub <noreply@github.com>",
                subject="Password reset request",
                body_plain=(
                    "We received a password change request. "
                    "Reset password: https://github.com/password_reset/abc. Ignore if not you."
                ),
            ),
            _pass(),
        ),
        (
            "legit_internal_urgency",
            "business",
            _msg(
                from_raw="Manager <manager@company.com>",
                subject="Action required: Q3 report",
                body_plain="Please submit your Q3 report within 24 hours. Immediate action required for the board meeting.",
            ),
            _pass(),
        ),
        (
            "legit_unsigned_marketing",
            "newsletter",
            _msg(
                from_raw="Shop <promo@smallshop.example>",
                subject="Weekly deals",
                body_plain="This week's deals are live. Visit our store for details.",
            ),
            _none(),
        ),
        (
            "legit_docusign",
            "docusign",
            _msg(
                from_raw="DocuSign <dse_na4@docusign.net>",
                subject="Please DocuSign: NDA",
                body_plain="Please review and sign: https://na4.docusign.net/Signing/StartInSession.aspx",
            ),
            _pass(),
        ),
        (
            "legit_clean_business",
            "business",
            _msg(
                from_raw="Alice <alice@partner.org>",
                subject="Meeting notes",
                body_plain="Thanks for the call. Attached are the notes from today.",
            ),
            _pass(),
        ),
    ]

    for case_id, category, parsed, auth in benign_specs:
        cases.append(ValidationCase(
            id=case_id, label="benign", category=category,
            parsed=parsed, auth=auth, expected_ceiling="Medium",
        ))

    # --- Malicious -----------------------------------------------------------
    malicious_specs = [
        (
            "phish_paypal_spoof",
            "phishing",
            _msg(
                from_raw="PayPal Security <no-reply@paypa1-secure.com>",
                reply_to_raw="support@evil.tk",
                subject="Urgent: Your account has been limited",
                body_html=(
                    "<p>Verify your account within 24 hours or it will be suspended. "
                    'Confirm your password: <a href="http://185.220.101.7/login">Click here</a></p>'
                ),
            ),
            _fail(),
        ),
        (
            "phish_bec_wire",
            "bec",
            _msg(
                from_raw="CEO <ceo@company-secure.tk>",
                subject="Urgent: Wire transfer needed",
                body_plain=(
                    "Immediate action required. Process wire transfer for invoice #9921. "
                    "Bitcoin payment also accepted. Account will be terminated within 24 hours."
                ),
            ),
            _none(),
        ),
        (
            "phish_credential_microsoft",
            "phishing",
            _msg(
                from_raw="IT Support <it@microsft-support.ru>",
                subject="Security alert: password expired",
                body_plain=(
                    "Unauthorized login attempt detected. Your password expired. "
                    "Reset your password immediately and enter credentials at "
                    "http://login-microsoft.ru/verify to restore account."
                ),
            ),
            _fail(),
        ),
        (
            "phish_malware_attachment",
            "malware",
            _msg(
                from_raw="Billing <invoices@vendor-secure.tk>",
                subject="Invoice attached - payment overdue",
                body_plain="Please review the attached invoice #4401 and complete the wire transfer.",
                attachments=[
                    Attachment(
                        filename="Invoice_4401.pdf.exe",
                        declared_extension="exe",
                        true_type="exe",
                        size_bytes=4096,
                        is_executable=True,
                        has_double_extension=True,
                    )
                ],
            ),
            _none(),
        ),
        (
            "phish_lookalike_docusign",
            "spoofing",
            _msg(
                from_raw="DocuSign <noreply@d0cusign-secure.xyz>",
                subject="Documents awaiting your signature",
                body_plain="Please verify your account to review the document: http://d0cusign-secure.xyz/login",
            ),
            _fail(),
        ),
    ]

    for case_id, category, parsed, auth in malicious_specs:
        cases.append(ValidationCase(
            id=case_id, label="malicious", category=category,
            parsed=parsed, auth=auth, expected_floor="High",
        ))

    return cases
