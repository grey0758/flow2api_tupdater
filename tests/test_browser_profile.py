import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import AsyncMock
from token_updater.browser_profile import configure_web_only_profile
from token_updater.browser import BrowserManager


class WebOnlyProfileTests(unittest.TestCase):
    def test_existing_browser_refresh_tokens_protect_profile_even_without_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            default=Path(root)/"Default";default.mkdir()
            with closing(sqlite3.connect(default/"Web Data")) as db:
                db.execute("CREATE TABLE token_service (service TEXT)")
                db.execute("INSERT INTO token_service VALUES ('existing')")
                db.commit()
            self.assertEqual(configure_web_only_profile(root), "preserved_browser_account")
            self.assertFalse((default/"Preferences").exists())

    def test_preserves_preferences_and_records_original_settings_once(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/"Default/Preferences";path.parent.mkdir()
            path.write_text(json.dumps({"signin":{"allowed":True},"profile":{"name":"Original"}}))
            self.assertEqual(configure_web_only_profile(root), "configured")
            self.assertEqual(configure_web_only_profile(root), "unchanged")
            result=json.loads(path.read_text())
            self.assertEqual(result["profile"], {"name":"Original"})
            self.assertEqual(result["signin"], {"allowed":False,"allowed_on_next_startup":False})
            self.assertEqual(json.loads((path.parent/".tupdater-browser-signin-backup.json").read_text()), {"allowed":True})

    def test_preserves_existing_browser_account(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/"Default/Preferences";path.parent.mkdir()
            original=json.dumps({"account_info":[{"email":"user@example.invalid"}]})
            path.write_text(original)
            self.assertEqual(configure_web_only_profile(root), "preserved_browser_account")
            self.assertEqual(path.read_text(), original)

    def test_invalid_preferences_are_never_replaced(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/"Default/Preferences";path.parent.mkdir();path.write_text('{broken')
            with self.assertRaises(ValueError):configure_web_only_profile(root)
            self.assertEqual(path.read_text(), '{broken')


class BrowserLaunchTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_launch_options_preserved_and_preferences_written_before_launch(self):
        with tempfile.TemporaryDirectory() as root:
            async def launch(**kwargs):
                self.assertFalse(json.loads((Path(root)/"Default/Preferences").read_text())["signin"]["allowed"])
                return "context"
            manager=BrowserManager()
            manager._playwright=SimpleNamespace(chromium=SimpleNamespace(launch_persistent_context=AsyncMock(side_effect=launch)))
            options={"user_data_dir":root,"headless":False,"proxy":{"server":"socks5://127.0.0.1:20001"},"args":["--example"]}
            self.assertEqual(await manager._launch_persistent_context(**options), "context")
            manager._playwright.chromium.launch_persistent_context.assert_awaited_once_with(**options)
