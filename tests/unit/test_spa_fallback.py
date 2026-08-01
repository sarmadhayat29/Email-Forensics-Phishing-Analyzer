"""SPA refresh / deep-link fallback must resolve to index.html, not a missing file."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from server import resolve_spa_file


class TestSpaFallback(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.dist = Path(self._tmpdir.name)
        (self.dist / "assets").mkdir()
        (self.dist / "index.html").write_text("<!doctype html><title>SPA</title>", encoding="utf-8")
        (self.dist / "shield.svg").write_text("<svg></svg>", encoding="utf-8")
        (self.dist / "assets" / "app.js").write_text("console.log('ok')", encoding="utf-8")
        self.index = str(self.dist / "index.html")

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_home_resolves_to_index(self):
        self.assertEqual(resolve_spa_file(str(self.dist), ""), self.index)
        self.assertEqual(resolve_spa_file(str(self.dist), "/"), self.index)

    def test_client_routes_resolve_to_index(self):
        for path in (
            "dashboard",
            "login",
            "signup",
            "history",
            "upload",
            "about",
            "analysis/abc-123",
            "analysis/nested/deep",
        ):
            self.assertEqual(
                resolve_spa_file(str(self.dist), path),
                self.index,
                msg=path,
            )

    def test_real_static_file_is_served(self):
        target = resolve_spa_file(str(self.dist), "shield.svg")
        self.assertEqual(target, str(self.dist / "shield.svg"))
        self.assertTrue(os.path.isfile(target))

    def test_asset_file_is_served(self):
        target = resolve_spa_file(str(self.dist), "assets/app.js")
        self.assertEqual(target, str(self.dist / "assets" / "app.js"))

    def test_path_traversal_falls_back_to_index(self):
        target = resolve_spa_file(str(self.dist), "../secrets.txt")
        self.assertEqual(target, self.index)


if __name__ == "__main__":
    unittest.main()
