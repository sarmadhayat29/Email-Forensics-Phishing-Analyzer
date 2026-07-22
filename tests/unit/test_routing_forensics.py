import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from models import ParsedMessage
from auth_checks import analyse_authentication
from routing import analyse_routing, classify_ip


class TestRoutingForensics(unittest.TestCase):

    def test_ip_classification(self):
        self.assertEqual(classify_ip("127.0.0.1"), "Loopback")
        self.assertEqual(classify_ip("192.168.1.50"), "Private (RFC 1918)")
        self.assertEqual(classify_ip("10.0.5.1"), "Private (RFC 1918)")
        self.assertEqual(classify_ip("172.16.0.1"), "Private (RFC 1918)")
        self.assertEqual(classify_ip("100.64.1.1"), "CGNAT")
        self.assertEqual(classify_ip("8.8.8.8"), "Public")
        self.assertEqual(classify_ip("invalid-ip"), "Invalid IP")

    def test_auth_checks_and_inconsistencies(self):
        parsed = ParsedMessage(
            from_raw="attacker@phish.com",
            authentication_results=[
                "mx.google.com; spf=pass (google.com: domain of bounce@legit-service.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=bounce@legit-service.com; dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=phish.com"
            ]
        )
        auth_verdict = analyse_authentication(parsed)
        self.assertEqual(auth_verdict.spf, "pass")
        self.assertEqual(auth_verdict.dmarc, "fail")
        self.assertTrue(any("SPF Alignment Failure" in inc for inc in auth_verdict.inconsistencies))

    def test_routing_timeline_and_delay(self):
        received_chain = [
            "from mx.google.com (mx.google.com [172.217.1.1]) by dest.com with ESMTP id 123; Wed, 22 Jul 2026 10:05:00 +0000",
            "from relay.origin.com (relay.origin.com [203.0.113.5]) by mx.google.com with ESMTP id 456; Wed, 22 Jul 2026 10:00:00 +0000"
        ]
        parsed = ParsedMessage(received_chain=received_chain)
        routing_verdict = analyse_routing(parsed)

        self.assertEqual(routing_verdict.hop_count, 2)
        self.assertEqual(len(routing_verdict.timeline), 2)

        hop1 = routing_verdict.timeline[0]
        hop2 = routing_verdict.timeline[1]

        self.assertEqual(hop1.hop_number, 1)
        self.assertEqual(hop1.from_host, "relay.origin.com")
        self.assertEqual(hop1.delay_display, "Origin")

        self.assertEqual(hop2.hop_number, 2)
        self.assertEqual(hop2.from_host, "mx.google.com")
        self.assertEqual(hop2.delay_display, "+5m 0s")

    def test_routing_time_travel_anomaly(self):
        # Hop 2 occurs chronologically BEFORE Hop 1
        received_chain = [
            "from mx.google.com (mx.google.com [172.217.1.1]) by dest.com with ESMTP id 123; Wed, 22 Jul 2026 09:50:00 +0000",
            "from relay.origin.com (relay.origin.com [203.0.113.5]) by mx.google.com with ESMTP id 456; Wed, 22 Jul 2026 10:00:00 +0000"
        ]
        parsed = ParsedMessage(received_chain=received_chain)
        routing_verdict = analyse_routing(parsed)

        self.assertTrue(any("time travel" in flag.lower() for flag in routing_verdict.flags))

    def test_routing_suspicious_private_ip(self):
        # Public IP hop followed by private IP hop
        received_chain = [
            "from internal.local (internal.local [192.168.1.100]) by dest.com with ESMTP id 123; Wed, 22 Jul 2026 10:05:00 +0000",
            "from wan.public.com (wan.public.com [64.233.160.1]) by internal.local with ESMTP id 456; Wed, 22 Jul 2026 10:00:00 +0000"
        ]
        parsed = ParsedMessage(received_chain=received_chain)
        routing_verdict = analyse_routing(parsed)

        self.assertTrue(any("private ip" in flag.lower() for flag in routing_verdict.flags))



if __name__ == '__main__':
    unittest.main()
