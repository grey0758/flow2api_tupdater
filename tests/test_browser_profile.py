import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from token_updater.browser_profile import configure_web_only_profile
from token_updater.browser import BrowserManager, LOGIN_BROWSER_ARGS


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
    def test_verified_existing_project_wins_over_browser_recency(self):
        manager = BrowserManager()
        bound = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
        recent = "5a1afeaf-d8d4-46c6-ae8b-eea49280cd64"
        profile = {
            "observed_flow_project_verified": 1,
            "observed_flow_project_identity": "owner@example.invalid",
            "observed_flow_project_id": bound,
        }
        self.assertEqual(
            manager._trusted_flow_project_id(
                profile, "OWNER@example.invalid", recent
            ),
            bound,
        )

    def test_unverified_project_uses_current_browser_observation(self):
        manager = BrowserManager()
        recent = "5a1afeaf-d8d4-46c6-ae8b-eea49280cd64"
        self.assertEqual(
            manager._trusted_flow_project_id(
                {"observed_flow_project_verified": 0},
                "owner@example.invalid",
                recent,
            ),
            recent,
        )

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

    def test_mutable_last_used_child_profile_fails_closed_without_binding(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            (root_path / "Profile 2").mkdir()
            (root_path / "Local State").write_text(
                json.dumps({"profile": {"last_used": "Profile 2"}})
            )
            with self.assertRaisesRegex(ValueError, "no trusted binding"):
                BrowserManager._selected_chromium_profile(root)

    def test_default_and_missing_local_state_keep_single_profile_behavior(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertIsNone(BrowserManager._selected_chromium_profile(root))
            (Path(root) / "Local State").write_text(
                json.dumps({"profile": {"last_used": "Default"}})
            )
            self.assertIsNone(BrowserManager._selected_chromium_profile(root))

    def test_root_managed_binding_overrides_mutable_last_used_profile(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            (root_path / "Profile 2").mkdir()
            (root_path / "Local State").write_text(
                json.dumps({"profile": {"last_used": "Default"}})
            )
            (root_path / ".tupdater-chromium-profile").write_text("Profile 2\n")
            (root_path / ".tupdater-chromium-profile").chmod(0o600)
            self.assertEqual(
                BrowserManager._selected_chromium_profile(root), "Profile 2"
            )

    def test_root_managed_default_binding_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            (root_path / "Default").mkdir()
            (root_path / "Profile 1").mkdir()
            marker = root_path / ".tupdater-chromium-profile"
            marker.write_text("Default\n")
            marker.chmod(0o600)

            self.assertEqual(
                BrowserManager._selected_chromium_profile(root), "Default"
            )

    def test_rejects_unsafe_or_symlinked_child_profile(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            root_path = Path(root)
            marker = root_path / ".tupdater-chromium-profile"
            marker.write_text("../outside")
            marker.chmod(0o600)
            with self.assertRaises(ValueError):
                BrowserManager._selected_chromium_profile(root)

            marker.write_text("Profile 9")
            (root_path / "Profile 9").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                BrowserManager._selected_chromium_profile(root)

    def test_binding_must_be_control_owned_mode_0600(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            (root_path / "Profile 2").mkdir()
            marker = root_path / ".tupdater-chromium-profile"
            marker.write_text("Profile 2")
            marker.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                BrowserManager._selected_chromium_profile(root)

    async def test_nondefault_child_uses_transient_headed_context(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            (root_path / "Profile 2").mkdir()
            (root_path / "Local State").write_text(
                json.dumps({"profile": {"last_used": "Profile 2"}})
            )
            marker = root_path / ".tupdater-chromium-profile"
            marker.write_text("Profile 2")
            marker.chmod(0o600)
            context = SimpleNamespace(close=AsyncMock())
            launch = AsyncMock(return_value=context)
            manager = BrowserManager()
            manager._playwright = SimpleNamespace(
                chromium=SimpleNamespace(launch_persistent_context=launch)
            )
            manager._ensure_background_xvfb = AsyncMock(return_value=True)
            manager._stop_background_xvfb = AsyncMock()

            result = await manager._launch_persistent_context(
                user_data_dir=root,
                headless=True,
                args=["--example"],
            )
            self.assertIs(result, context)
            launch.assert_awaited_once_with(
                user_data_dir=root,
                headless=False,
                args=[*LOGIN_BROWSER_ARGS, "--profile-directory=Profile 2"],
            )
            await manager._close_context(context)
            context.close.assert_awaited_once()
            manager._stop_background_xvfb.assert_awaited_once()

    async def test_explicit_default_uses_transient_headed_context(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            (root_path / "Default").mkdir()
            (root_path / "Profile 1").mkdir()
            marker = root_path / ".tupdater-chromium-profile"
            marker.write_text("Default")
            marker.chmod(0o600)
            context = SimpleNamespace(close=AsyncMock())
            launch = AsyncMock(return_value=context)
            manager = BrowserManager()
            manager._playwright = SimpleNamespace(
                chromium=SimpleNamespace(launch_persistent_context=launch)
            )
            manager._ensure_background_xvfb = AsyncMock(return_value=True)
            manager._stop_background_xvfb = AsyncMock()

            result = await manager._launch_persistent_context(
                user_data_dir=root,
                headless=True,
                args=["--example"],
            )

            self.assertIs(result, context)
            launch.assert_awaited_once_with(
                user_data_dir=root,
                headless=False,
                args=[*LOGIN_BROWSER_ARGS, "--profile-directory=Default"],
            )
            await manager._close_context(context)
            context.close.assert_awaited_once()
            manager._stop_background_xvfb.assert_awaited_once()

    async def test_failed_child_launch_stops_owned_xvfb(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            (root_path / "Profile 3").mkdir()
            (root_path / "Local State").write_text(
                json.dumps({"profile": {"last_used": "Profile 3"}})
            )
            marker = root_path / ".tupdater-chromium-profile"
            marker.write_text("Profile 3")
            marker.chmod(0o600)
            manager = BrowserManager()
            manager._playwright = SimpleNamespace(
                chromium=SimpleNamespace(
                    launch_persistent_context=AsyncMock(
                        side_effect=RuntimeError("launch failed")
                    )
                )
            )
            manager._ensure_background_xvfb = AsyncMock(return_value=True)
            manager._stop_background_xvfb = AsyncMock()
            with self.assertRaises(RuntimeError):
                await manager._launch_persistent_context(
                    user_data_dir=root, headless=True, args=[]
                )
            manager._stop_background_xvfb.assert_awaited_once()

    async def test_failed_auth_preserves_verified_identity_project_binding(self):
        manager = BrowserManager()
        with patch(
            "token_updater.browser.profile_db.update_profile", AsyncMock()
        ) as update:
            await manager._persist_login_state(17, None)

        update.assert_awaited_once_with(17, is_logged_in=0)

    async def test_successful_peek_persists_complete_rotated_cookie_snapshot(self):
        manager = BrowserManager()
        manager._validate_context_session = AsyncMock(return_value={
            "success": True,
            "session_token": "rotated-session",
            "email": "owner@example.test",
        })
        manager._save_google_cookies_from_context = AsyncMock(return_value=True)
        context = SimpleNamespace(cookies=AsyncMock(return_value=[
            {"name": "SID", "value": "root", "domain": ".google.com", "path": "/"},
            {"name": "OSID", "value": "flow", "domain": "flow.google.com", "path": "/"},
        ]))

        token = await manager._peek_context_session({"id": 18}, context)

        self.assertEqual(token, "rotated-session")
        manager._save_google_cookies_from_context.assert_awaited_once_with(18, context)
