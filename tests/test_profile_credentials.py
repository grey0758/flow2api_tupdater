import unittest

from token_updater import api


class ProfileCredentialHelperTests(unittest.TestCase):
    def test_google_browser_seed_keeps_flow_host_cookie_scope(self):
        raw = '[{"name":"OSID","value":"flow","domain":"flow.google.com","path":"/"},{"name":"SID","value":"google","domain":".google.com","path":"/"}]'
        self.assertEqual(api._google_browser_seed(raw)[0]["domain"], "flow.google.com")
        self.assertEqual(api._google_browser_seed("SID=value; OSID=unscoped"), [{"name":"SID","value":"value","domain":".google.com","path":"/"}])

    def test_parse_account_import_content_supports_two_and_three_columns(self):
        items = api._parse_account_import_content(
            "主账号,alpha@example.com,pass-1\nbeta@example.com,pass-2\n"
        )

        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["name"], "主账号")
        self.assertEqual(items[0]["login_account"], "alpha@example.com")
        self.assertEqual(items[0]["login_password"], "pass-1")
        self.assertEqual(items[1]["name"], "beta@example.com")
        self.assertEqual(items[1]["login_account"], "beta@example.com")
        self.assertEqual(items[1]["login_password"], "pass-2")

    def test_parse_account_import_content_reports_line_number(self):
        with self.assertRaises(api.HTTPException) as ctx:
            api._parse_account_import_content("only-one-column")

        self.assertIn("第 1 行", str(ctx.exception.detail))

    def test_resolve_login_credentials_requires_complete_pair(self):
        with self.assertRaises(api.HTTPException):
            api._resolve_login_credentials("", "", "alpha@example.com", None)

    def test_normalize_cookie_export_kind_supports_aliases(self):
        self.assertEqual(api._normalize_cookie_export_kind(None), "google")
        self.assertEqual(api._normalize_cookie_export_kind("session"), "session")
        self.assertEqual(api._normalize_cookie_export_kind("labs"), "session")
        self.assertEqual(api._normalize_cookie_export_kind("google"), "google")
        self.assertEqual(api._normalize_cookie_export_kind("protocol"), "google")

    def test_normalize_cookie_export_kind_rejects_unknown_kind(self):
        with self.assertRaises(api.HTTPException) as ctx:
            api._normalize_cookie_export_kind("unknown")

        self.assertIn("session / google", str(ctx.exception.detail))

    def test_build_google_cookie_export_preserves_structured_cookie_items(self):
        profile = {
            "id": 3,
            "name": "alpha",
            "google_cookies": '[{"name":"SID","value":"aaa","domain":".google.com"},{"name":"HSID","value":"bbb","domain":"accounts.google.com"}]',
        }

        data = api._build_google_cookie_export(profile)

        self.assertTrue(data["success"])
        self.assertEqual(data["profile_id"], 3)
        self.assertEqual(data["kind"], "google")
        self.assertEqual(data["cookie_count"], 2)
        self.assertEqual(data["filename"], "profile-3-google-cookies.json")
        self.assertEqual(data["cookies"][0]["domain"], ".google.com")
        self.assertIn('"name": "SID"', data["cookies_json"])

    def test_build_google_cookie_export_supports_plain_text_cookie_string(self):
        profile = {
            "id": 8,
            "name": "beta",
            "google_cookies": "SID=aaa; HSID=bbb; SAPISID=ccc",
        }

        data = api._build_google_cookie_export(profile)

        self.assertEqual(data["profile_id"], 8)
        self.assertEqual(data["cookie_count"], 3)
        self.assertEqual(data["cookies"][1]["name"], "HSID")
        self.assertEqual(data["cookies"][2]["value"], "ccc")

    def test_serialize_profile_masks_password_by_default(self):
        profile = {
            "id": 7,
            "name": "alpha",
            "login_account": "alpha@example.com",
            "login_password": "secret-pass-123",
            "flow2api_url": "",
            "connection_token_override": "",
            "proxy_url": "",
        }

        data = api._serialize_profile(profile, active_id=None)
        self.assertTrue(data["has_login_credentials"])
        self.assertEqual(data["login_account"], "alpha@example.com")
        self.assertNotIn("login_password", data)
        self.assertEqual(data["login_password_preview"], "secr...-123")

        detail = api._serialize_profile(profile, active_id=7, include_secret=True)
        self.assertEqual(detail["login_password"], "secret-pass-123")
        self.assertTrue(detail["is_browser_active"])


if __name__ == "__main__":
    unittest.main()
