import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from models import ParsedMessage
from url_analysis import analyze_urls


class TestURLAnalysis(unittest.TestCase):

    def test_clean_urls(self):
        parsed = ParsedMessage(
            body_html='<a href="https://company.com/about">About Us</a>',
            body_plain="Visit https://company.com/help"
        )
        verdict = analyze_urls(parsed)
        self.assertEqual(verdict.total_urls, 2)
        self.assertEqual(verdict.suspicious_count, 0)

    def test_mismatched_hyperlink_anchor(self):
        parsed = ParsedMessage(
            body_html='<a href="http://evil-attacker.com/login">https://paypal.com/signin</a>'
        )
        verdict = analyze_urls(parsed)
        self.assertEqual(verdict.total_urls, 1)
        url_obj = verdict.urls[0]
        self.assertTrue(url_obj.is_mismatched_anchor)
        self.assertTrue(any("Mismatched Hyperlink" in f for f in url_obj.findings))

    def test_ip_based_url_and_shortener(self):
        parsed = ParsedMessage(
            body_html='<a href="http://192.168.1.50/admin">Click</a> <a href="http://bit.ly/xyz">Short</a>'
        )
        verdict = analyze_urls(parsed)
        self.assertEqual(verdict.total_urls, 2)
        self.assertTrue(verdict.urls[0].is_ip_based)
        self.assertTrue(verdict.urls[1].is_shortener)

    def test_open_redirect_and_high_risk_tld(self):
        parsed = ParsedMessage(
            body_html='<a href="http://cheap-deals.xyz/gateway?redirect=https://evil.com">Click</a>'
        )
        verdict = analyze_urls(parsed)
        self.assertEqual(verdict.total_urls, 1)
        url_obj = verdict.urls[0]
        self.assertTrue(url_obj.is_suspicious_domain)
        self.assertTrue(any("open-redirect" in f for f in url_obj.findings))


if __name__ == '__main__':
    unittest.main()
