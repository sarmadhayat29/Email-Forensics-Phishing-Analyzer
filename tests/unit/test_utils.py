import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from utils import (
    extract_address,
    extract_domain,
    extract_display_name,
    looks_like_lookalike,
    is_plausible_hostname,
    registrable_domain,
    build_match_text,
    HIGH_RISK_TLDS,
    RISKY_EXTENSIONS,
    SHORTENER_DOMAINS,
)


class TestAddressParsing(unittest.TestCase):

    def test_display_name_spoofing_does_not_flip_domain(self):
        """A brand address hidden in the display name must not win over the real one."""
        header = '"billing@paypal.com" <thief@evil.tk>'
        self.assertEqual(extract_address(header), "thief@evil.tk")
        self.assertEqual(extract_domain(header), "evil.tk")
        self.assertEqual(extract_display_name(header), "billing@paypal.com")

    def test_ordinary_headers(self):
        self.assertEqual(extract_domain("PayPal <no-reply@paypal.com>"), "paypal.com")
        self.assertEqual(extract_domain("bob@example.com"), "example.com")
        self.assertEqual(extract_domain("<bounce@mail.example.co.uk>"), "mail.example.co.uk")
        self.assertEqual(extract_display_name("John Doe <john@company.com>"), "John Doe")

    def test_missing_or_malformed(self):
        self.assertIsNone(extract_domain(""))
        self.assertIsNone(extract_domain("not an address"))
        self.assertIsNone(extract_address(""))
        self.assertEqual(extract_display_name(""), "")


class TestHostnamePlausibility(unittest.TestCase):

    def test_filenames_and_versions_are_not_hostnames(self):
        for candidate in ["invoice.pdf", "report.docx", "2.1", "release.v2.1", "Inc.", ".com"]:
            self.assertFalse(is_plausible_hostname(candidate), candidate)

    def test_real_hostnames(self):
        for candidate in ["paypal.com", "www.company.co.uk", "portal.giki.edu.pk", "evil.tk"]:
            self.assertTrue(is_plausible_hostname(candidate), candidate)

    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("www.example.com"), "example.com")
        self.assertEqual(registrable_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("portal.giki.edu.pk"), "giki.edu.pk")
        self.assertEqual(registrable_domain(""), "")


class TestLookalikeDetection(unittest.TestCase):

    def test_homoglyph_and_typosquat(self):
        self.assertEqual(looks_like_lookalike("paypa1.com"), "paypal")
        self.assertEqual(looks_like_lookalike("micros0ft.com"), "microsoft")
        self.assertEqual(looks_like_lookalike("payapl.com"), "paypal")

    def test_brand_token_containment(self):
        """Brand names embedded as a label token must be caught."""
        self.assertEqual(looks_like_lookalike("paypal-secure.com"), "paypal")
        self.assertEqual(looks_like_lookalike("paypa1-secure.com"), "paypal")
        self.assertEqual(looks_like_lookalike("secure-microsoft-login.tk"), "microsoft")
        self.assertEqual(looks_like_lookalike("paypal.evil.tk"), "paypal")
        self.assertEqual(looks_like_lookalike("netflix-billing.xyz"), "netflix")

    def test_brand_owned_domains_are_exempt(self):
        for domain in [
            "paypal.com", "login.paypal.com", "paypal.me", "amazon.co.uk",
            "outlook.office.com", "outlook.office365.com",
            "login.microsoftonline.com", "mail.google.com", "amazonses.com",
            "dropboxmail.com", "facebookmail.com", "adobesign.com", "squareup.com",
        ]:
            self.assertIsNone(looks_like_lookalike(domain), domain)

    def test_benign_domains_are_not_lookalikes(self):
        """Short or word-embedded brand tokens must not create false positives."""
        for domain in [
            "pineapple-farm.com", "follow-ups.com", "town-square.com",
            "giki.edu.pk", "legit-company.com", "cheap-deals.xyz",
            "some-domain.com", "compromised-server.net",
        ]:
            self.assertIsNone(looks_like_lookalike(domain), domain)

    def test_empty_input(self):
        self.assertIsNone(looks_like_lookalike(""))
        self.assertIsNone(looks_like_lookalike("."))


class TestMatchTextNormalization(unittest.TestCase):

    def test_html_tags_and_entities_are_stripped(self):
        text = build_match_text("", "<p>Please <b>verify</b> your account</p>")
        self.assertIn("verify your account", text)
        self.assertNotIn("<b>", text)

    def test_script_and_style_bodies_are_dropped(self):
        text = build_match_text("", "<style>.a{color:red}</style><script>var x=1</script><p>Hello</p>")
        self.assertNotIn("color:red", text)
        self.assertNotIn("var x", text)
        self.assertIn("Hello", text)

    def test_zero_width_and_intra_word_tag_obfuscation(self):
        """conf<zero-width>irm and pass<b>word</b> must still read as plain text."""
        text = build_match_text("", "conf&#8203;irm your pass<b>word</b>")
        self.assertIn("confirm your password", text)

    def test_soft_hyphen_is_removed(self):
        self.assertIn("password", build_match_text("pass\u00adword", ""))

    def test_empty_bodies(self):
        self.assertEqual(build_match_text("", ""), "")
        self.assertEqual(build_match_text(None, None), "")


class TestSharedConstants(unittest.TestCase):

    def test_high_risk_tld_set_is_shared(self):
        """All three engines must consult the same TLD blocklist."""
        import scoring
        import url_analysis
        import header_analysis
        self.assertIs(scoring.HIGH_RISK_TLDS, HIGH_RISK_TLDS)
        self.assertIs(url_analysis.HIGH_RISK_TLDS, HIGH_RISK_TLDS)
        self.assertIs(header_analysis.HIGH_RISK_TLDS, HIGH_RISK_TLDS)
        # Union of the three former lists.
        for tld in {"xyz", "top", "tk", "icu", "rest", "monster", "live"}:
            self.assertIn(tld, HIGH_RISK_TLDS)

    def test_expanded_lists(self):
        for ext in {"lnk", "iso", "img", "chm", "xll", "vhd"}:
            self.assertIn(ext, RISKY_EXTENSIONS)
        for host in {"bit.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"}:
            self.assertIn(host, SHORTENER_DOMAINS)


if __name__ == '__main__':
    unittest.main()
