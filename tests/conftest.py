"""Shared test configuration.

Live authentication re-verification and WHOIS domain-age lookups are switched
off for the whole suite so no test can accidentally depend on DNS, WHOIS or the
internet. Tests that exercise those paths enable them explicitly and inject
fake resolvers / verifiers / WHOIS callables.
"""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

os.environ["LIVE_AUTH_ENABLED"] = "false"
os.environ["DOMAIN_AGE_ENABLED"] = "false"
# Empty means "in-memory only", so the suite never touches the cache file.
os.environ["WHOIS_CACHE_FILE"] = ""
